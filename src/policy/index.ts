import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import {
  MODULE_NAMES,
  SEVERITIES,
  isModuleName,
  isSeverity,
  sortFindings,
  type Finding,
  type ModuleName,
  type Severity,
} from '../core/finding.js';

export const POLICY_FILE_NAME = 'fullshield.policy.json';
export const POLICY_FLAG = 'FULLSHIELD_EXPERIMENTAL_POLICY';

export const POLICY_PEER_ERROR =
  'fullshield policy requires optional peer zod. Install with: npm i -D zod';

export class PolicyError extends Error {}

export interface PolicyException {
  ruleId: string;
  file?: string;
  id?: string;
  owner: string;
  reason: string;
  /** ISO date (`YYYY-MM-DD`) or datetime. */
  expires: string;
}

export interface FullShieldPolicy {
  requiredModules?: ModuleName[];
  severityOverrides?: Partial<Record<string, Severity>>;
  failOn?: Record<string, Severity>;
  exceptions?: PolicyException[];
}

export interface PolicyLoadOptions {
  experimental?: boolean;
  /** Phase 555. When `recommended` or `ci-strict`, load policy without the experimental flag. */
  profile?: string;
}

export interface ApplyPolicyContext {
  branch?: string;
  modulesRun?: readonly ModuleName[];
  now?: Date;
}

export interface AppliedPolicy {
  findings: Finding[];
  failOn?: Severity;
  errors: string[];
}

type ZodNamespace = typeof import('zod').z;

export type ZodLoader = () => Promise<{ z: ZodNamespace }>;

const defaultLoadZod: ZodLoader = async () => {
  const zodMod = (await import('zod')) as { z?: ZodNamespace } & ZodNamespace;
  const z = zodMod.z ?? zodMod;
  return { z };
};

const PROFILE_POLICY = new Set(['recommended', 'ci-strict']);

export function isPolicyEnabled(opts: PolicyLoadOptions = {}): boolean {
  if (opts.experimental === true || process.env[POLICY_FLAG] === '1') {return true;}
  return typeof opts.profile === 'string' && PROFILE_POLICY.has(opts.profile);
}

function formatZodIssues(error: { issues: Array<{ path: PropertyKey[]; message: string }> }): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.map(String).join('.');
      return path.length > 0 ? `${path}: ${issue.message}` : issue.message;
    })
    .join('; ');
}

function isIsoTimestamp(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}(T[\d:.+-Z]+)?$/.test(value)) {return false;}
  return Number.isFinite(Date.parse(value));
}

function policySchema(z: ZodNamespace) {
  const severity = z.enum(SEVERITIES);
  const moduleName = z.enum(MODULE_NAMES);
  const isoExpires = z
    .string()
    .min(1)
    .refine(isIsoTimestamp, { message: 'expires must be an ISO date' });
  return z
    .object({
      requiredModules: z.array(moduleName).optional(),
      severityOverrides: z.record(z.string(), severity).optional(),
      failOn: z.record(z.string(), severity).optional(),
      exceptions: z
        .array(
          z.object({
            ruleId: z.string().min(1),
            file: z.string().min(1).optional(),
            id: z.string().min(1).optional(),
            owner: z.string().min(1, 'exceptions require owner'),
            reason: z.string().min(1, 'exceptions require reason'),
            expires: isoExpires,
          }),
        )
        .optional(),
    })
    .strict();
}

/** Parse and validate a policy document with the optional zod peer (lazy-imported). */
export async function parsePolicy(
  raw: unknown,
  source = POLICY_FILE_NAME,
  loadZod: ZodLoader = defaultLoadZod,
): Promise<FullShieldPolicy> {
  let z: ZodNamespace;
  try {
    ({ z } = await loadZod());
  } catch {
    throw new PolicyError(POLICY_PEER_ERROR);
  }
  const parsed = policySchema(z).safeParse(raw);
  if (!parsed.success) {
    throw new PolicyError(`${source}: ${formatZodIssues(parsed.error)}`);
  }
  const data = parsed.data;
  const requiredModules = data.requiredModules?.filter(isModuleName);
  const severityOverrides: FullShieldPolicy['severityOverrides'] = {};
  if (data.severityOverrides !== undefined) {
    for (const [ruleId, severity] of Object.entries(data.severityOverrides)) {
      if (isSeverity(severity)) {severityOverrides[ruleId] = severity;}
    }
  }
  const failOn: Record<string, Severity> = {};
  if (data.failOn !== undefined) {
    for (const [branch, severity] of Object.entries(data.failOn)) {
      if (isSeverity(severity)) {failOn[branch] = severity;}
    }
  }
  return {
    requiredModules,
    severityOverrides: Object.keys(severityOverrides).length > 0 ? severityOverrides : undefined,
    failOn: Object.keys(failOn).length > 0 ? failOn : undefined,
    exceptions: data.exceptions,
  };
}

/** Load `fullshield.policy.json` when the experimental flag is on. Missing file → undefined. */
export async function loadPolicy(
  cwd: string,
  opts: PolicyLoadOptions = {},
  loadZod: ZodLoader = defaultLoadZod,
): Promise<FullShieldPolicy | undefined> {
  if (!isPolicyEnabled(opts)) {return undefined;}
  const file = join(cwd, POLICY_FILE_NAME);
  let contents: string;
  try {
    contents = await readFile(file, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {return undefined;}
    throw new PolicyError(`cannot read policy file ${file}: ${code ?? String(error)}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(contents) as unknown;
  } catch (error) {
    throw new PolicyError(
      `${file}: invalid JSON (${error instanceof Error ? error.message : String(error)})`,
    );
  }
  return parsePolicy(raw, file, loadZod);
}

function globMatch(pattern: string, value: string): boolean {
  if (pattern === '*') {return true;}
  if (!pattern.includes('*')) {return pattern === value;}
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(value);
}

export function failOnForBranch(
  map: Record<string, Severity> | undefined,
  branch: string,
): Severity | undefined {
  if (map === undefined) {return undefined;}
  if (Object.prototype.hasOwnProperty.call(map, branch)) {return map[branch];}
  for (const [key, severity] of Object.entries(map)) {
    if (key === '*') {continue;}
    if (globMatch(key, branch)) {return severity;}
  }
  return map['*'];
}

export function resolvePolicyBranch(cwd: string, env: NodeJS.ProcessEnv = process.env): string {
  const fromEnv =
    env.FULLSHIELD_POLICY_BRANCH ?? env.GITHUB_HEAD_REF ?? env.GITHUB_REF_NAME ?? env.CI_COMMIT_BRANCH;
  if (fromEnv !== undefined && fromEnv.length > 0) {return fromEnv;}
  try {
    const stdout = execFileSync('git', ['-C', cwd, 'rev-parse', '--abbrev-ref', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const branch = stdout.trim();
    return branch.length > 0 ? branch : '*';
  } catch {
    return '*';
  }
}

function expiresAtMs(expires: string): number {
  if (/^\d{4}-\d{2}-\d{2}$/.test(expires)) {
    return Date.parse(`${expires}T23:59:59.999Z`);
  }
  return Date.parse(expires);
}

function exceptionMatches(exception: PolicyException, finding: Finding): boolean {
  if (exception.ruleId !== finding.ruleId) {return false;}
  if (exception.id !== undefined && exception.id !== finding.id) {return false;}
  if (exception.file !== undefined && exception.file !== finding.file) {return false;}
  return true;
}

/** Apply severity overrides, branch failOn, and exceptions. Expired exceptions become CI errors. */
export function applyPolicy(
  findings: readonly Finding[],
  policy: FullShieldPolicy,
  ctx: ApplyPolicyContext = {},
): AppliedPolicy {
  const now = ctx.now ?? new Date();
  const errors: string[] = [];
  const overrides = policy.severityOverrides ?? {};
  let next = findings.map((finding) => {
    const severity = overrides[finding.ruleId];
    return severity !== undefined && severity !== finding.severity
      ? { ...finding, severity }
      : finding;
  });

  const suppressed = new Set<string>();
  for (const exception of policy.exceptions ?? []) {
    if (expiresAtMs(exception.expires) < now.getTime()) {
      errors.push(
        `policy exception for ${exception.ruleId} expired on ${exception.expires} (owner: ${exception.owner}); renew or remove it`,
      );
      continue;
    }
    for (const finding of next) {
      if (exceptionMatches(exception, finding)) {suppressed.add(finding.id);}
    }
  }
  next = next.filter((finding) => !suppressed.has(finding.id));

  for (const required of policy.requiredModules ?? []) {
    if (!(ctx.modulesRun ?? []).includes(required)) {
      errors.push(`policy required module "${required}" did not run`);
    }
  }

  return {
    findings: sortFindings(next),
    failOn: failOnForBranch(policy.failOn, ctx.branch ?? '*'),
    errors,
  };
}

export function mergeRequiredModules(
  requested: readonly ModuleName[],
  required: readonly ModuleName[] | undefined,
): ModuleName[] {
  if (required === undefined || required.length === 0) {return [...requested];}
  const out = [...requested];
  for (const name of required) {
    if (!out.includes(name)) {out.push(name);}
  }
  return out;
}

export { renderPrSummary, ruleDocsUrl } from './prSummary.js';
