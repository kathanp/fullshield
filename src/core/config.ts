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

export interface ResolvedConfig {
  modules: ModuleName[];
  failOn: Severity;
  ignore: string[];
  baseline: string;
  notify: NotifyConfig;
  deps: DepsConfig;
}

export const DEFAULT_CONFIG: ResolvedConfig = {
  modules: [...MODULE_NAMES],
  failOn: 'high',
  ignore: ['dist/**', '**/*.test.ts'],
  baseline: '.fullshield-baseline.json',
  notify: { slackWebhookEnv: 'FULLSHIELD_SLACK_WEBHOOK' },
  deps: { offline: false },
};

export class ConfigError extends Error {}

const KNOWN_KEYS = new Set(['modules', 'failOn', 'ignore', 'baseline', 'notify', 'deps']);

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
