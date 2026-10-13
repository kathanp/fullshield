import { stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';

import { configModule } from '../modules/config/index.js';
import { depsModule } from '../modules/deps/index.js';
import { sastModule } from '../modules/sast/index.js';
import { secretsModule } from '../modules/secrets/index.js';
import { loadConfig, type ResolvedConfig } from './config.js';
import { walkFiles } from './fileWalker.js';
import { listStagedFiles } from './git.js';
import {
  sortFindings,
  summarize,
  type Finding,
  type FindingSummary,
  type ModuleName,
} from './finding.js';
import { packageVersion } from './version.js';

export interface ModuleContext {
  cwd: string;
  /** Posix-style relative paths of every scannable file under cwd. */
  files: string[];
  config: ResolvedConfig;
}

export interface ScanModule {
  name: ModuleName;
  run(ctx: ModuleContext): Promise<Finding[]>;
}

export interface ScanOptions {
  /** Directory to scan. Defaults to process.cwd(). */
  cwd?: string;
  /** Subset of modules to run. Defaults to config.modules. */
  modules?: ModuleName[];
  /** Explicit path to fullshield.config.json. */
  configPath?: string;
  /** Scan only files staged in git (pre-commit mode). */
  staged?: boolean;
  /** Cache-only OSV lookups (no network). */
  offline?: boolean;
}

export interface ScanMetadata {
  version: string;
  startedAt: string;
  durationMs: number;
  cwd: string;
  filesScanned: number;
  modulesRequested: ModuleName[];
  /** Requested modules that are actually implemented and ran. */
  modulesRun: ModuleName[];
}

export interface ScanResult {
  findings: Finding[];
  summary: FindingSummary;
  metadata: ScanMetadata;
  config: ResolvedConfig;
}

/**
 * Scanner modules register here as their phases are built.
 * Phase 5: deps + secrets + sast + config.
 */
export const builtinModules: readonly ScanModule[] = [depsModule, secretsModule, sastModule, configModule];

export const IMPLEMENTED_MODULES: readonly ModuleName[] = builtinModules.map((m) => m.name);

function dedupe(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    if (!seen.has(finding.id)) {
      seen.add(finding.id);
      out.push(finding);
    }
  }
  return out;
}

/**
 * Core scan: load config, walk files, run the requested modules that exist,
 * then dedupe, sort, and summarize findings. `modules` is injectable so the
 * engine's orchestration is testable independently of built-in modules.
 */
export async function runScan(
  options: ScanOptions = {},
  modules: readonly ScanModule[] = builtinModules,
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const t0 = performance.now();

  const cwd = resolve(options.cwd ?? process.cwd());
  const stats = await stat(cwd).catch(() => null);
  if (stats === null || !stats.isDirectory()) {
    throw new Error(`scan path is not a directory: ${cwd}`);
  }

  let config = await loadConfig(cwd, options.configPath);
  if (options.offline === true) {
    config = { ...config, deps: { ...config.deps, offline: true } };
  }
  const modulesRequested = options.modules ?? config.modules;
  let files = await walkFiles({ cwd, ignore: config.ignore });
  if (options.staged === true) {
    const staged = new Set(await listStagedFiles(cwd));
    files = files.filter((file) => staged.has(file));
  }

  const available = new Map(modules.map((m) => [m.name, m]));
  const modulesRun = modulesRequested.filter((name) => available.has(name));

  const ctx: ModuleContext = { cwd, files, config };
  const collected: Finding[] = [];
  for (const name of modulesRun) {
    const module = available.get(name);
    if (module !== undefined) {
      collected.push(...(await module.run(ctx)));
    }
  }

  const findings = sortFindings(dedupe(collected));
  return {
    findings,
    summary: summarize(findings),
    metadata: {
      version: packageVersion(),
      startedAt,
      durationMs: Math.round((performance.now() - t0) * 100) / 100,
      cwd,
      filesScanned: files.length,
      modulesRequested: [...modulesRequested],
      modulesRun,
    },
    config,
  };
}

/** Public library API: scan with the built-in modules. */
export function scan(options: ScanOptions = {}): Promise<ScanResult> {
  return runScan(options);
}
