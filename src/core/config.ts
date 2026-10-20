import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

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
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) throw new ConfigError(`${source}: "sast.sources" must be an array`);
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
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) throw new ConfigError(`${source}: "sast.sanitizers" must be an array`);
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

function validate(raw: unknown, source: string): Partial<ResolvedConfig> {
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
  const out: Partial<ResolvedConfig> = {};
  if (record.modules !== undefined) {
    if (!Array.isArray(record.modules)) {
      throw new ConfigError(`${source}: "modules" must be an array`);
    }
    out.modules = record.modules.map((m) => {
      if (typeof m !== 'string' || !isModuleName(m)) {
        throw new ConfigError(
          `${source}: unknown module "${String(m)}" (valid: ${MODULE_NAMES.join(', ')})`,
        );
      }
      return m;
    });
  }
  if (record.failOn !== undefined) {
    if (typeof record.failOn !== 'string' || !isSeverity(record.failOn)) {
      throw new ConfigError(
        `${source}: invalid "failOn" severity ${JSON.stringify(record.failOn)}`,
      );
    }
    out.failOn = record.failOn;
  }
  if (record.ignore !== undefined) {
    if (
      !Array.isArray(record.ignore) ||
      record.ignore.some((p) => typeof p !== 'string')
    ) {
      throw new ConfigError(`${source}: "ignore" must be an array of glob strings`);
    }
    out.ignore = record.ignore as string[];
  }
  if (record.baseline !== undefined) {
    if (typeof record.baseline !== 'string') {
      throw new ConfigError(`${source}: "baseline" must be a string path`);
    }
    out.baseline = record.baseline;
  }
  if (record.notify !== undefined) {
    const notify = record.notify;
    if (
      typeof notify !== 'object' ||
      notify === null ||
      typeof (notify as Record<string, unknown>).slackWebhookEnv !== 'string'
    ) {
      throw new ConfigError(
        `${source}: "notify" must be an object with a "slackWebhookEnv" string`,
      );
    }
    out.notify = { slackWebhookEnv: (notify as { slackWebhookEnv: string }).slackWebhookEnv };
  }
  if (record.deps !== undefined) {
    if (typeof record.deps !== 'object' || record.deps === null || Array.isArray(record.deps)) {
      throw new ConfigError(`${source}: "deps" must be an object`);
    }
    const rawDeps = record.deps as Record<string, unknown>;
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
    out.deps = deps;
  }
  if (record.ai !== undefined) {
    if (typeof record.ai !== 'object' || record.ai === null || Array.isArray(record.ai)) {
      throw new ConfigError(`${source}: "ai" must be an object`);
    }
    const rawAi = record.ai as Record<string, unknown>;
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
    out.ai = ai;
  }
  if (record.defaultExcludes !== undefined) {
    if (typeof record.defaultExcludes !== 'boolean') {
      throw new ConfigError(`${source}: "defaultExcludes" must be a boolean`);
    }
    out.defaultExcludes = record.defaultExcludes;
  }
  if (record.excludes !== undefined) {
    if (
      !Array.isArray(record.excludes) ||
      record.excludes.some((p) => typeof p !== 'string')
    ) {
      throw new ConfigError(`${source}: "excludes" must be an array of glob strings`);
    }
    out.excludes = record.excludes as string[];
  }
  if (record.sast !== undefined) {
    if (typeof record.sast !== 'object' || record.sast === null || Array.isArray(record.sast)) {
      throw new ConfigError(`${source}: "sast" must be an object`);
    }
    const rawSast = record.sast as Record<string, unknown>;
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
    out.sast = sast;
  }
  if (record.types !== undefined) {
    if (typeof record.types !== 'object' || record.types === null || Array.isArray(record.types)) {
      throw new ConfigError(`${source}: "types" must be an object`);
    }
    const rawTypes = record.types as Record<string, unknown>;
    const types: TypesConfig = { maxFiles: DEFAULT_CONFIG.types.maxFiles };
    if (rawTypes.maxFiles !== undefined) {
      if (typeof rawTypes.maxFiles !== 'number' || !Number.isInteger(rawTypes.maxFiles) || rawTypes.maxFiles < 1) {
        throw new ConfigError(`${source}: "types.maxFiles" must be a positive integer`);
      }
      types.maxFiles = rawTypes.maxFiles;
    }
    out.types = types;
  }
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
