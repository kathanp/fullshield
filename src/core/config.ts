import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { isCapabilityName, type CapabilityName } from '../capabilities/names.js';
import { parsePrivateRegistry } from '../modules/deps/private-reg.js';
import type { CapabilityPolicy } from '../capabilities/policy.js';
import {
  MODULE_NAMES,
  isModuleName,
  isSeverity,
  type ModuleName,
  type Severity,
} from './finding.js';

export const CONFIG_FILE_NAME = 'fullshield.config.json';

export interface NotifyConfig {
  slackWebhookEnv: string;
}

export interface DepsConfig {
  /** When true, OSV is never contacted; cache only. */
  offline: boolean;
  /** Cache root (contains an `osv/` directory). Relative paths are resolved from cwd. */
  cacheDir?: string;
  /** Present only when FULLSHIELD_EXPERIMENTAL_CAPABILITIES=1. */
  capabilityPolicy?: CapabilityPolicy;
  /** Present only when FULLSHIELD_EXPERIMENTAL_LICENSE_POLICY=1. */
  licenseDeny?: string[];
  /** Present only when FULLSHIELD_EXPERIMENTAL_LICENSE_POLICY=1. */
  licenseAllow?: string[];
  /** Present only when FULLSHIELD_EXPERIMENTAL_PRIVATE_REG=1. Stored, never fetched. */
  registry?: string;
  /** Present only when FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL=1. Local file only. */
  epssFile?: string;
}

export interface AiConfig {
  /** Off by default. Also enabled by `--ai`. */
  enabled: boolean;
  /** Hard cap per scan (spec §16.1). */
  maxCostUsd: number;
  /** Highest-severity findings sent to the model first. */
  maxFindings: number;
}

export interface SastSourceConfig {
  callee: string;
  returns: 'tainted';
}

export interface SastSanitizerConfig {
  callee: string;
  clears: string[];
}

export interface SastConfig {
  /** Files larger than this are not parsed. Reported as SAST-SKIP-001. */
  maxFileBytes: number;
  /** Present only when FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS=1. */
  sources?: SastSourceConfig[];
  sanitizers?: SastSanitizerConfig[];
}

/** Phase 80. The TypeScript program is not built above `maxFiles`. */
export interface TypesConfig {
  maxFiles: number;
}

export interface ResolvedConfig {
  modules: ModuleName[];
  failOn: Severity;
  ignore: string[];
  /** When false, generated/vendored/minified excludes are not applied. */
  defaultExcludes: boolean;
  /** Replaces the built-in exclude list when set. */
  excludes?: string[];
  baseline: string;
  notify: NotifyConfig;
  deps: DepsConfig;
  ai: AiConfig;
  sast: SastConfig;
  types: TypesConfig;
  /** Phase 90. Path to a user Semgrep-style YAML file. Read only when the experimental flag is on. */
  semgrepRules?: string;
  /** Phase 553. Documented bundle of existing defaults; does not enable experimental SAST. */
  profile?: ProfileName;
}

const PROFILE_NAMES = [
  'recommended',
  'ci-strict',
  'pr-fast',
  'prod-monitor',
] as const;

export type ProfileName = (typeof PROFILE_NAMES)[number];

function isProfileName(value: string): value is ProfileName {
  return (PROFILE_NAMES as readonly string[]).includes(value);
}

export const DEFAULT_CONFIG: ResolvedConfig = {
  modules: [...MODULE_NAMES],
  failOn: 'high',
  ignore: ['dist/**', '**/*.test.ts'],
  defaultExcludes: true,
  baseline: '.fullshield-baseline.json',
  notify: { slackWebhookEnv: 'FULLSHIELD_SLACK_WEBHOOK' },
  deps: { offline: false },
  ai: { enabled: false, maxCostUsd: 1, maxFindings: 50 },
  sast: { maxFileBytes: 1024 * 1024 },
  types: { maxFiles: 5000 },
};

export class ConfigError extends Error {}

const KNOWN_KEYS = new Set([
  'modules',
  'failOn',
  'ignore',
  'defaultExcludes',
  'excludes',
  'baseline',
  'notify',
  'deps',
  'ai',
  'sast',
  'types',
  'semgrepRules',
  'profile',
]);

const SAST_CLASSES = new Set([
  'sqli',
  'nosqli',
  'cmdi',
  'path',
  'xss',
  'ssrf',
  'redirect',
  'eval',
  'jwt',
  'crypto',
  'proto',
  'secrets',
  'deps',
  'config',
]);

function parseSastSources(value: unknown, source: string): SastSourceConfig[] | undefined {
  if (value === undefined) {return undefined;}
  if (!Array.isArray(value)) {throw new ConfigError(`${source}: "sast.sources" must be an array`);}
  return value.map((item) => {
    if (typeof item !== 'object' || item === null) {
      throw new ConfigError(`${source}: "sast.sources" entries must be objects`);
    }
    const row = item as Record<string, unknown>;
    if (typeof row.callee !== 'string' || row.callee.length === 0) {
      throw new ConfigError(`${source}: "sast.sources[].callee" must be a string`);
    }
    if (row.returns !== 'tainted') {
      throw new ConfigError(`${source}: "sast.sources[].returns" must be "tainted"`);
    }
    return { callee: row.callee, returns: 'tainted' };
  });
}

function parseSastSanitizers(value: unknown, source: string): SastSanitizerConfig[] | undefined {
  if (value === undefined) {return undefined;}
  if (!Array.isArray(value)) {throw new ConfigError(`${source}: "sast.sanitizers" must be an array`);}
  return value.map((item) => {
    if (typeof item !== 'object' || item === null) {
      throw new ConfigError(`${source}: "sast.sanitizers" entries must be objects`);
    }
    const row = item as Record<string, unknown>;
    if (typeof row.callee !== 'string' || row.callee.length === 0) {
      throw new ConfigError(`${source}: "sast.sanitizers[].callee" must be a string`);
    }
    if (!Array.isArray(row.clears) || row.clears.some((name) => typeof name !== 'string' || !SAST_CLASSES.has(name))) {
      throw new ConfigError(`${source}: "sast.sanitizers[].clears" must be B4 class names`);
    }
    return { callee: row.callee, clears: row.clears.filter((name) => name !== 'secrets' && name !== 'deps') };
  });
}

function parseCapabilityGlobs(
  value: unknown,
  source: string,
  label: string,
): Partial<Record<CapabilityName, readonly string[]>> {
  if (value === undefined) {return {};}
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ConfigError(`${source}: "${label}" must be an object`);
  }
  const out: Partial<Record<CapabilityName, readonly string[]>> = {};
  for (const [key, globs] of Object.entries(value)) {
    if (!isCapabilityName(key)) {throw new ConfigError(`${source}: unknown capability "${key}"`);}
    if (!Array.isArray(globs) || globs.some((item) => typeof item !== 'string' || item.length === 0)) {
      throw new ConfigError(`${source}: "${label}.${key}" must be an array of package globs`);
    }
    out[key] = globs;
  }
  return out;
}

function parseCapabilityPolicy(value: unknown, source: string): CapabilityPolicy {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ConfigError(`${source}: "deps.capabilityPolicy" must be an object`);
  }
  const raw = value as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (key !== 'deny' && key !== 'warn') {
      throw new ConfigError(`${source}: unknown key "deps.capabilityPolicy.${key}"`);
    }
  }
  return {
    deny: parseCapabilityGlobs(raw.deny, source, 'deps.capabilityPolicy.deny'),
    warn: parseCapabilityGlobs(raw.warn, source, 'deps.capabilityPolicy.warn'),
  };
}

function asConfigRecord(raw: unknown, source: string): Record<string, unknown> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ConfigError(`${source}: config must be a JSON object`);
  }
  const record = raw as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!KNOWN_KEYS.has(key)) {
      throw new ConfigError(
        `${source}: unknown key "${key}" (known keys: ${[...KNOWN_KEYS].join(', ')})`,
      );
    }
  }
  return record;
}

function parseModulesField(value: unknown, source: string): ModuleName[] {
  if (!Array.isArray(value)) {
    throw new ConfigError(`${source}: "modules" must be an array`);
  }
  return value.map((m) => {
    if (typeof m !== 'string' || !isModuleName(m)) {
      throw new ConfigError(
        `${source}: unknown module "${String(m)}" (valid: ${MODULE_NAMES.join(', ')})`,
      );
    }
    return m;
  });
}

function parseFailOnField(value: unknown, source: string): Severity {
  if (typeof value !== 'string' || !isSeverity(value)) {
    throw new ConfigError(`${source}: invalid "failOn" severity ${JSON.stringify(value)}`);
  }
  return value;
}

function parseStringGlobs(value: unknown, source: string, label: string): string[] {
  if (!Array.isArray(value) || value.some((p) => typeof p !== 'string')) {
    throw new ConfigError(`${source}: "${label}" must be an array of glob strings`);
  }
  return value as string[];
}

function parseNotifyField(value: unknown, source: string): NotifyConfig {
  if (
    typeof value !== 'object' ||
    value === null ||
    typeof (value as Record<string, unknown>).slackWebhookEnv !== 'string'
  ) {
    throw new ConfigError(`${source}: "notify" must be an object with a "slackWebhookEnv" string`);
  }
  return { slackWebhookEnv: (value as { slackWebhookEnv: string }).slackWebhookEnv };
}

function parseDepsField(value: unknown, source: string): DepsConfig {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ConfigError(`${source}: "deps" must be an object`);
  }
  const rawDeps = value as Record<string, unknown>;
  const deps: DepsConfig = { offline: false };
  if (rawDeps.offline !== undefined) {
    if (typeof rawDeps.offline !== 'boolean') {
      throw new ConfigError(`${source}: "deps.offline" must be a boolean`);
    }
    deps.offline = rawDeps.offline;
  }
  if (rawDeps.cacheDir !== undefined) {
    if (typeof rawDeps.cacheDir !== 'string') {
      throw new ConfigError(`${source}: "deps.cacheDir" must be a string`);
    }
    deps.cacheDir = rawDeps.cacheDir;
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_CAPABILITIES === '1' && rawDeps.capabilityPolicy !== undefined) {
    deps.capabilityPolicy = parseCapabilityPolicy(rawDeps.capabilityPolicy, source);
  }
  applyParityDeps(deps, rawDeps, source);
  return deps;
}

function applyParityDeps(deps: DepsConfig, rawDeps: Record<string, unknown>, source: string): void {
  if (process.env.FULLSHIELD_EXPERIMENTAL_LICENSE_POLICY === '1') {
    if (rawDeps.licenseDeny !== undefined) {
      deps.licenseDeny = parseStringGlobs(rawDeps.licenseDeny, source, 'deps.licenseDeny');
    }
    if (rawDeps.licenseAllow !== undefined) {
      deps.licenseAllow = parseStringGlobs(rawDeps.licenseAllow, source, 'deps.licenseAllow');
    }
  }
  applyRegistry(deps, rawDeps, source);
  applyEpssFile(deps, rawDeps, source);
}

function applyRegistry(deps: DepsConfig, rawDeps: Record<string, unknown>, source: string): void {
  if (process.env.FULLSHIELD_EXPERIMENTAL_PRIVATE_REG !== '1' || rawDeps.registry === undefined) {return;}
  if (typeof rawDeps.registry !== 'string') {
    throw new ConfigError(`${source}: "deps.registry" must be a string`);
  }
  parsePrivateRegistry(rawDeps.registry);
  deps.registry = rawDeps.registry;
}

function applyEpssFile(deps: DepsConfig, rawDeps: Record<string, unknown>, source: string): void {
  if (process.env.FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL !== '1' || rawDeps.epssFile === undefined) {return;}
  if (typeof rawDeps.epssFile !== 'string' || rawDeps.epssFile.length === 0) {
    throw new ConfigError(`${source}: "deps.epssFile" must be a path (FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL)`);
  }
  deps.epssFile = rawDeps.epssFile;
}

function parseAiField(value: unknown, source: string): AiConfig {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ConfigError(`${source}: "ai" must be an object`);
  }
  const rawAi = value as Record<string, unknown>;
  const ai: AiConfig = { enabled: false, maxCostUsd: 1, maxFindings: 50 };
  if (rawAi.enabled !== undefined) {
    if (typeof rawAi.enabled !== 'boolean') {
      throw new ConfigError(`${source}: "ai.enabled" must be a boolean`);
    }
    ai.enabled = rawAi.enabled;
  }
  if (rawAi.maxCostUsd !== undefined) {
    if (typeof rawAi.maxCostUsd !== 'number' || rawAi.maxCostUsd < 0) {
      throw new ConfigError(`${source}: "ai.maxCostUsd" must be a non-negative number`);
    }
    ai.maxCostUsd = rawAi.maxCostUsd;
  }
  if (rawAi.maxFindings !== undefined) {
    if (typeof rawAi.maxFindings !== 'number' || rawAi.maxFindings < 1) {
      throw new ConfigError(`${source}: "ai.maxFindings" must be a positive number`);
    }
    ai.maxFindings = rawAi.maxFindings;
  }
  return ai;
}

function parseSastField(value: unknown, source: string): SastConfig {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ConfigError(`${source}: "sast" must be an object`);
  }
  const rawSast = value as Record<string, unknown>;
  const sast: SastConfig = { maxFileBytes: 1024 * 1024 };
  if (rawSast.maxFileBytes !== undefined) {
    if (typeof rawSast.maxFileBytes !== 'number' || rawSast.maxFileBytes < 1) {
      throw new ConfigError(`${source}: "sast.maxFileBytes" must be a positive number`);
    }
    sast.maxFileBytes = rawSast.maxFileBytes;
  }
  const custom = process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS === '1';
  if (!custom && (rawSast.sources !== undefined || rawSast.sanitizers !== undefined)) {
    throw new ConfigError(
      `${source}: unknown key "sast.sources" (FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS)`,
    );
  }
  if (custom) {
    sast.sources = parseSastSources(rawSast.sources, source);
    sast.sanitizers = parseSastSanitizers(rawSast.sanitizers, source);
  }
  return sast;
}

function parseTypesField(value: unknown, source: string): TypesConfig {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ConfigError(`${source}: "types" must be an object`);
  }
  const rawTypes = value as Record<string, unknown>;
  const types: TypesConfig = { maxFiles: DEFAULT_CONFIG.types.maxFiles };
  if (rawTypes.maxFiles !== undefined) {
    if (typeof rawTypes.maxFiles !== 'number' || !Number.isInteger(rawTypes.maxFiles) || rawTypes.maxFiles < 1) {
      throw new ConfigError(`${source}: "types.maxFiles" must be a positive integer`);
    }
    types.maxFiles = rawTypes.maxFiles;
  }
  return types;
}

function parseProfileField(value: unknown, source: string): ProfileName {
  if (typeof value !== 'string' || !isProfileName(value)) {
    throw new ConfigError(
      `${source}: invalid "profile" ${JSON.stringify(value)} (valid: ${PROFILE_NAMES.join(', ')})`,
    );
  }
  return value;
}

function applyCoreFields(
  out: Partial<ResolvedConfig>,
  record: Record<string, unknown>,
  source: string,
): void {
  if (record.modules !== undefined) {out.modules = parseModulesField(record.modules, source);}
  if (record.failOn !== undefined) {out.failOn = parseFailOnField(record.failOn, source);}
  if (record.ignore !== undefined) {out.ignore = parseStringGlobs(record.ignore, source, 'ignore');}
  if (record.baseline !== undefined) {
    if (typeof record.baseline !== 'string') {
      throw new ConfigError(`${source}: "baseline" must be a string path`);
    }
    out.baseline = record.baseline;
  }
  if (record.notify !== undefined) {out.notify = parseNotifyField(record.notify, source);}
  if (record.deps !== undefined) {out.deps = parseDepsField(record.deps, source);}
  if (record.ai !== undefined) {out.ai = parseAiField(record.ai, source);}
}

function applyExtraFields(
  out: Partial<ResolvedConfig>,
  record: Record<string, unknown>,
  source: string,
): void {
  if (record.defaultExcludes !== undefined) {
    if (typeof record.defaultExcludes !== 'boolean') {
      throw new ConfigError(`${source}: "defaultExcludes" must be a boolean`);
    }
    out.defaultExcludes = record.defaultExcludes;
  }
  if (record.excludes !== undefined) {
    out.excludes = parseStringGlobs(record.excludes, source, 'excludes');
  }
  if (record.sast !== undefined) {out.sast = parseSastField(record.sast, source);}
  if (record.types !== undefined) {out.types = parseTypesField(record.types, source);}
  if (record.semgrepRules !== undefined) {
    if (typeof record.semgrepRules !== 'string' || record.semgrepRules.length === 0) {
      throw new ConfigError(`${source}: "semgrepRules" must be a path string`);
    }
    out.semgrepRules = record.semgrepRules;
  }
  if (record.profile !== undefined) {out.profile = parseProfileField(record.profile, source);}
}

function validate(raw: unknown, source: string): Partial<ResolvedConfig> {
  const record = asConfigRecord(raw, source);
  const out: Partial<ResolvedConfig> = {};
  applyCoreFields(out, record, source);
  applyExtraFields(out, record, source);
  return out;
}

/**
 * Load fullshield.config.json from `configPath` (must exist) or from
 * `<cwd>/fullshield.config.json` (optional), merged over defaults.
 */
export async function loadConfig(cwd: string, configPath?: string): Promise<ResolvedConfig> {
  const explicit = configPath !== undefined;
  const file = explicit ? resolve(cwd, configPath) : join(cwd, CONFIG_FILE_NAME);

  let contents: string;
  try {
    contents = await readFile(file, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (!explicit && code === 'ENOENT') {
      return structuredClone(DEFAULT_CONFIG);
    }
    throw new ConfigError(`cannot read config file ${file}: ${code ?? String(error)}`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(contents);
  } catch (error) {
    throw new ConfigError(
      `${file}: invalid JSON (${error instanceof Error ? error.message : String(error)})`,
    );
  }

  return { ...structuredClone(DEFAULT_CONFIG), ...validate(raw, file) };
}
