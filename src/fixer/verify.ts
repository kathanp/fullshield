import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, posix, resolve } from 'node:path';

import { loadConfig } from '../core/config.js';
import type { Finding } from '../core/finding.js';
import { lineIndependentFingerprint } from '../core/fingerprint.js';
import { walkFiles } from '../core/fileWalker.js';
import { literalString, walk } from '../modules/sast/ast.js';
import { runConfigAstChecks } from '../modules/config/astChecks.js';
import { parseSource, runSastOnText } from '../modules/sast/engine.js';
import { runInterproc } from '../modules/sast/interproc.js';
import { crossFileReturnFindings } from '../modules/sast/returns.js';
import type { ParsedSource } from '../modules/sast/interproc.js';
import type { AstNode } from '../modules/sast/types.js';
import { scanTextForSecrets } from '../modules/secrets/index.js';
import { applyUnifiedDiff } from './patches.js';
import { collectManifestOverrides } from './override.js';

export const FIX_VERIFY_FLAG = 'FULLSHIELD_EXPERIMENTAL_FIX_VERIFY';

export type FixVerification = 'removes-finding' | 'does-not-remove' | 'introduces-finding';

const SOURCE_EXT = /\.[cm]?[jt]sx?$/;
const MAX_BYTES = 1024 * 1024;

export function fixVerifyEnabled(explicit?: boolean): boolean {
  return explicit === true || process.env[FIX_VERIFY_FLAG] === '1';
}

/** `--yes` does not authorize a patch that introduces a finding. */
export function allowPatchWrite(
  verified: FixVerification | undefined,
  options: { enabled: boolean; forceUnverified?: boolean; yes?: boolean },
): boolean {
  if (!options.enabled) return true;
  if (verified === 'introduces-finding') return options.yes === true ? false : false;
  if (verified === 'removes-finding') return true;
  return options.forceUnverified === true;
}

export function verificationWarning(ruleId: string, file: string, status: FixVerification): string | undefined {
  if (status === 'does-not-remove') {
    return `warning: ${ruleId} ${file} does not remove the finding; pass --force-unverified to write it`;
  }
  if (status === 'introduces-finding') {
    return `warning: ${ruleId} ${file} introduces a finding and was not written`;
  }
  return undefined;
}

export interface VerifyInput {
  cwd: string;
  file: string;
  ruleId: string;
  line?: number;
  diff: string;
  base?: string;
  finding?: Finding;
  cacheDir?: string;
}

export async function verifyProposedChange(
  input: VerifyInput,
): Promise<{ status: FixVerification; scanned: string[] }> {
  if (isDependencyChange(input)) {
    const cacheDir = input.cacheDir ?? (await resolveCacheDir(input.cwd));
    const base = input.base ?? (await readOptional(input.cwd, input.file));
    return {
      status: await classifyDependency(input, base, cacheDir),
      scanned: [normalizeRel(input.file)],
    };
  }
  const patchFile = normalizeRel(input.file);
  const base = input.base ?? (await readOptional(input.cwd, patchFile)) ?? '';
  const after = applyUnifiedDiff(base, input.diff);
  const projectFiles = await walkFiles({ cwd: input.cwd });
  const sourceFiles = projectFiles.filter((file) => SOURCE_EXT.test(file));
  const importers = await directImporters(input.cwd, patchFile, sourceFiles);
  const targetFile = normalizeRel(input.finding?.file ?? patchFile);
  const scanned = [...new Set([patchFile, targetFile, ...importers])].sort();
  const beforeOverlay = new Map<string, string>([[patchFile, base]]);
  const afterOverlay = new Map<string, string>([[patchFile, after]]);
  const before = await collectFindings(input.cwd, scanned, beforeOverlay);
  const afterFindings = await collectFindings(input.cwd, scanned, afterOverlay);
  return { status: classifyCode(before, afterFindings, input.ruleId, targetFile), scanned };
}

export async function writeIfAllowed(
  input: VerifyInput & { forceUnverified?: boolean; yes?: boolean },
): Promise<{ status: FixVerification; written: boolean; warning?: string; scanned: string[] }> {
  const verdict = await verifyProposedChange(input);
  const warning = verificationWarning(input.ruleId, input.file, verdict.status);
  const allowed = allowPatchWrite(verdict.status, {
    enabled: true,
    forceUnverified: input.forceUnverified,
    yes: input.yes,
  });
  if (!allowed) {
    return { status: verdict.status, written: false, warning, scanned: verdict.scanned };
  }
  const base = input.base ?? (await readOptional(input.cwd, input.file)) ?? '';
  const next = applyUnifiedDiff(base, input.diff);
  if (next === base) {
    return { status: verdict.status, written: false, scanned: verdict.scanned };
  }
  const abs = join(input.cwd, input.file);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, next);
  return { status: verdict.status, written: true, warning, scanned: verdict.scanned };
}

function isDependencyChange(input: VerifyInput): boolean {
  if (input.finding?.fix?.kind === 'dependency-bump' || input.finding?.fix?.kind === 'dependency-override') {
    return true;
  }
  if (input.ruleId.startsWith('DEPS-')) return true;
  if (/^# bump \S+ from \S+ to \S+/m.test(input.diff)) return true;
  return normalizeRel(input.file).endsWith('package.json') && /"(?:overrides|resolutions)"/.test(input.diff);
}

async function classifyDependency(
  input: VerifyInput,
  base: string | undefined,
  cacheDir: string,
): Promise<FixVerification> {
  const plans = plannedVersions(input.diff, base);
  if (plans.length === 0) return 'does-not-remove';
  const before = advisoryIds(input.finding);
  for (const plan of plans) {
    const after = await readCachedAdvisoryIds(cacheDir, plan.name, plan.to);
    if (after === undefined) return 'does-not-remove';
    for (const id of after) {
      if (!before.includes(id)) return 'introduces-finding';
    }
    if (before.length === 0 || before.some((id) => after.includes(id))) return 'does-not-remove';
  }
  return 'removes-finding';
}

function advisoryIds(finding: Finding | undefined): string[] {
  const refs = finding?.references ?? [];
  const ids = refs.filter((id) => /^[A-Z]+-/.test(id));
  return ids.length > 0 ? ids : refs.filter((id) => id.length > 0);
}

function plannedVersions(diff: string, base: string | undefined): Array<{ name: string; to: string }> {
  const bump = /^# bump (\S+) from \S+ to (\S+)/m.exec(diff);
  if (bump?.[1] !== undefined && bump[2] !== undefined) return [{ name: bump[1], to: bump[2] }];
  if (base === undefined) return [];
  const next = collectManifestOverrides(applyUnifiedDiff(base, diff));
  const prev = collectManifestOverrides(base);
  const plans: Array<{ name: string; to: string }> = [];
  for (const [name, version] of next) {
    if (prev.get(name) !== version) plans.push({ name, to: version });
  }
  return plans;
}

async function readCachedAdvisoryIds(cacheDir: string, name: string, version: string): Promise<string[] | undefined> {
  const file = join(cacheDir, 'osv', `${name.replaceAll('/', '__')}@${version}.json`);
  try {
    const raw = JSON.parse(await readFile(file, 'utf8')) as { vulns?: unknown };
    if (!Array.isArray(raw.vulns)) return undefined;
    const ids: string[] = [];
    for (const vuln of raw.vulns) {
      if (vuln !== null && typeof vuln === 'object' && typeof (vuln as { id?: unknown }).id === 'string') {
        ids.push((vuln as { id: string }).id);
      }
    }
    return ids;
  } catch {
    return undefined;
  }
}

async function resolveCacheDir(cwd: string): Promise<string> {
  try {
    const config = await loadConfig(cwd);
    if (config.deps.cacheDir !== undefined) return resolve(cwd, config.deps.cacheDir);
  } catch {
    // Missing config uses the default cache directory. A missing entry is not a clear.
  }
  return join(homedir(), '.cache', 'fullshield');
}

function classifyCode(
  before: readonly Finding[],
  after: readonly Finding[],
  ruleId: string,
  file: string,
): FixVerification {
  const beforeFp = new Set(before.map((finding) => lineIndependentFingerprint(finding)));
  const introduced = after.some((finding) => !beforeFp.has(lineIndependentFingerprint(finding)));
  if (introduced) return 'introduces-finding';
  const remains = after.some((finding) => finding.ruleId === ruleId && normalizeRel(finding.file ?? '') === file);
  return remains ? 'does-not-remove' : 'removes-finding';
}

async function collectFindings(
  cwd: string,
  files: readonly string[],
  overlay: ReadonlyMap<string, string>,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const parsed: ParsedSource[] = [];
  for (const file of files) {
    const text = overlay.get(file) ?? (await readOptional(cwd, file));
    if (text === undefined || text.includes('\0') || text.length > MAX_BYTES || !SOURCE_EXT.test(file)) continue;
    try {
      findings.push(...(await runSastOnText(file, text)));
    } catch {
      // A file that does not parse contributes no SAST finding.
    }
    try {
      findings.push(...(await runConfigAstChecks(file, text)));
    } catch {
      // Config checks are skipped when the file does not parse.
    }
    findings.push(...scanTextForSecrets(file, text));
    try {
      const ast = await parseSource(text);
      parsed.push({ file, source: text, ast });
    } catch {
      // Importers that do not parse are omitted from the cross-file pass.
    }
  }
  if (parsed.length > 0) {
    findings.push(...runInterproc(parsed));
    findings.push(...crossFileReturnFindings(parsed));
  }
  return findings;
}

async function directImporters(cwd: string, target: string, files: readonly string[]): Promise<string[]> {
  const fileSet = new Set(files);
  const found: string[] = [];
  for (const file of files) {
    if (file === target) continue;
    const text = await readOptional(cwd, file);
    if (text === undefined || text.includes('\0') || text.length > MAX_BYTES) continue;
    let ast: AstNode;
    try {
      ast = await parseSource(text);
    } catch {
      continue;
    }
    if (importedFiles(file, ast, fileSet).has(target)) found.push(file);
  }
  return found;
}

function importedFiles(file: string, ast: AstNode, files: ReadonlySet<string>): Set<string> {
  const out = new Set<string>();
  const add = (spec: string | undefined): void => {
    if (spec === undefined || !spec.startsWith('.')) return;
    const resolved = resolveRelative(file, spec, files);
    if (resolved !== undefined) out.add(resolved);
  };
  walk(ast, (node) => {
    if (
      node.type === 'ImportDeclaration' ||
      node.type === 'ExportAllDeclaration' ||
      node.type === 'ExportNamedDeclaration'
    ) {
      add(node.source === null || node.source === undefined ? undefined : literalString(node.source));
      return;
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require') {
      const arg = node.arguments[0];
      add(arg !== undefined && arg.type !== 'SpreadElement' ? literalString(arg) : undefined);
    }
  });
  return out;
}

function resolveRelative(fromFile: string, spec: string, files: ReadonlySet<string>): string | undefined {
  const base = posix.normalize(posix.join(posix.dirname(fromFile), spec));
  const candidates = [
    base,
    `${base}.js`,
    `${base}.ts`,
    `${base}.mjs`,
    `${base}.cjs`,
    `${base}.jsx`,
    `${base}.tsx`,
    `${base}/index.js`,
    `${base}/index.ts`,
  ];
  return candidates.find((candidate) => files.has(candidate));
}

function normalizeRel(file: string): string {
  return file.replace(/\\/g, '/');
}

async function readOptional(cwd: string, file: string): Promise<string | undefined> {
  try {
    return await readFile(join(cwd, file), 'utf8');
  } catch {
    return undefined;
  }
}
