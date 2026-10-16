import { readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';

import { configModule } from '../modules/config/index.js';
import { depsModule } from '../modules/deps/index.js';
import { scanMcpConfig } from '../modules/mcp/index.js';
import { sastModule } from '../modules/sast/index.js';
import { secretsModule } from '../modules/secrets/index.js';
import { secretsAdvEnabled } from '../modules/secrets/experimental.js';
import type { SecretHit } from '../modules/secrets/types.js';
import { applyExplain, applyTriage } from '../ai/triage.js';
import { runLogicHunt } from '../ai/logic.js';
import { createAiClient, isInternalAi, isLiveAi } from '../ai/provider.js';
import { applyBaseline, readBaseline, writeBaseline } from './baseline.js';
import { loadConfig, type ResolvedConfig } from './config.js';
import { walkFiles } from './fileWalker.js';
import { listStagedFiles } from './git.js';
import { applyInlineSuppressions } from './suppression.js';
import {
  sortFindings,
  summarize,
  type Finding,
  type FindingSummary,
  type ModuleName,
  type Severity,
} from './finding.js';
import { packageVersion } from './version.js';
import {
  POLICY_FILE_NAME,
  applyPolicy,
  loadPolicy,
  mergeRequiredModules,
  resolvePolicyBranch,
  type FullShieldPolicy,
} from '../policy/index.js';

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
  /** Write the current (post-suppression) findings to the baseline file. */
  updateBaseline?: boolean;
  /** Opt-in AI: `true` enables the client; a string selects a mode. */
  ai?: boolean | 'triage' | 'explain' | 'logic';
  /** Phase 22 incremental (requires experimentalIncremental or FULLSHIELD_EXPERIMENTAL_PLATFORM=1). */
  changed?: boolean;
  since?: string;
  experimentalIncremental?: boolean;
  changedFiles?: string[];
  /** Phase 30: scan git history for secrets (`FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1`). */
  history?: boolean;
  /** Phase 30: scan a built client bundle directory. */
  bundle?: string;
  /** Phase 30: opt-in live identity check. Never default. Requires iOwnTheseCredentials. */
  verifySecrets?: boolean;
  iOwnTheseCredentials?: boolean;
  /** Injected fetch for --verify-secrets tests. */
  verifyFetch?: typeof fetch;
  /** Phase 33: scan MCP configs under the user home (requires FULLSHIELD_EXPERIMENTAL_MCPCFG=1). */
  includeHome?: boolean;
  /** Phase 34 policy-as-code (`FULLSHIELD_EXPERIMENTAL_POLICY=1`). */
  experimentalPolicy?: boolean;
  /** Override git/CI branch when applying `failOn` per branch. */
  policyBranch?: string;
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

export interface PolicyScanResult {
  enabled: true;
  file: string;
  failOn?: Severity;
  errors: string[];
  policy: FullShieldPolicy;
}

export interface ScanResult {
  findings: Finding[];
  summary: FindingSummary;
  metadata: ScanMetadata;
  config: ResolvedConfig;
  /** Present only when experimental policy was loaded from `fullshield.policy.json`. */
  policy?: PolicyScanResult;
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
  const maxRaw = process.env.FULLSHIELD_AI_MAX_FINDINGS;
  if (maxRaw !== undefined && maxRaw.length > 0) {
    const maxFindings = Number(maxRaw);
    if (Number.isFinite(maxFindings) && maxFindings >= 1) {
      config = { ...config, ai: { ...config.ai, maxFindings } };
    }
  }
  const loadedPolicy = await loadPolicy(cwd, { experimental: options.experimentalPolicy });
  const modulesRequested = mergeRequiredModules(
    options.modules ?? config.modules,
    loadedPolicy?.requiredModules,
  );
  let files = await walkFiles({ cwd, ignore: config.ignore });
  if (options.staged === true) {
    const staged = new Set(await listStagedFiles(cwd));
    files = files.filter((file) => staged.has(file));
  }
  const incrementalOn =
    options.experimentalIncremental === true || process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM === '1';
  if (incrementalOn && (options.changed === true || options.since !== undefined || options.changedFiles)) {
    const { resolveChangedFiles } = await import('../incremental/index.js');
    const listed =
      options.changedFiles ??
      resolveChangedFiles(cwd, {
        changed: options.changed,
        since: options.since,
        experimental: true,
      });
    if (listed.length > 0) {
      const allow = new Set(listed);
      files = files.filter((file) => allow.has(file));
    }
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
  if (process.env.FULLSHIELD_EXPERIMENTAL_MCPCFG === '1') {
    collected.push(
      ...scanMcpConfig(cwd, { experimental: true, includeHome: options.includeHome === true }),
    );
  }

  const extraHits: SecretHit[] = [];
  const secretsWanted = modulesRequested.includes('secrets');
  if (secretsAdvEnabled() && secretsWanted) {
    if (options.history === true) {
      const { scanGitHistory } = await import('../modules/secrets/history.js');
      const hist = await scanGitHistory(cwd);
      extraHits.push(...hist.hits);
      collected.push(...hist.findings);
    }
    if (options.bundle !== undefined && options.bundle.length > 0) {
      const { scanBundle } = await import('../modules/secrets/bundle.js');
      const bun = await scanBundle(options.bundle);
      extraHits.push(...bun.hits);
      collected.push(...bun.findings);
    }
  }

  const sources: Record<string, string> = {};
  for (const file of new Set(collected.map((f) => f.file).filter((f): f is string => f !== undefined))) {
    try {
      sources[file] = await readFile(join(cwd, file), 'utf8');
    } catch {
      // Finding file disappeared between walk and filter; keep the finding.
    }
  }
  const unsuppressed = applyInlineSuppressions(dedupe(collected), sources);
  const baselinePath = resolve(cwd, config.baseline);
  if (options.updateBaseline === true) {
    await writeBaseline(baselinePath, unsuppressed);
  }
  let findings = sortFindings(applyBaseline(unsuppressed, await readBaseline(baselinePath)));

  if (
    secretsAdvEnabled() &&
    secretsWanted &&
    options.verifySecrets === true &&
    options.iOwnTheseCredentials === true
  ) {
    const { applyVerification } = await import('../modules/secrets/verify.js');
    const { scanTextForSecretHits } = await import('../modules/secrets/index.js');
    const secretById = new Map<string, string>();
    for (const hit of extraHits) {
      if (hit.secret !== undefined) secretById.set(hit.finding.id, hit.secret);
    }
    for (const finding of findings) {
      if (finding.module !== 'secrets' || finding.file === undefined || secretById.has(finding.id)) {
        continue;
      }
      let text = sources[finding.file];
      if (text === undefined) {
        try {
          text = await readFile(join(cwd, finding.file), 'utf8');
        } catch {
          continue;
        }
      }
      for (const hit of scanTextForSecretHits(finding.file, text)) {
        if (hit.secret !== undefined) secretById.set(hit.finding.id, hit.secret);
      }
    }
    findings = sortFindings(
      await applyVerification(findings, secretById, {
        fetchImpl: options.verifyFetch,
      }),
    );
  }

  let policyResult: PolicyScanResult | undefined;
  if (loadedPolicy !== undefined) {
    const applied = applyPolicy(findings, loadedPolicy, {
      branch: options.policyBranch ?? resolvePolicyBranch(cwd),
      modulesRun,
    });
    findings = applied.findings;
    policyResult = {
      enabled: true,
      file: join(cwd, POLICY_FILE_NAME),
      failOn: applied.failOn,
      errors: applied.errors,
      policy: loadedPolicy,
    };
  }

  const aiMode = options.ai;
  const aiEnabled =
    aiMode === true ||
    aiMode === 'triage' ||
    aiMode === 'explain' ||
    aiMode === 'logic' ||
    config.ai.enabled;
  if (aiEnabled) {
    const client = createAiClient({
      enabled: true,
      config: { ...config.ai, enabled: true },
      useFixtures: !isLiveAi(),
    });
    const mode = typeof aiMode === 'string' ? aiMode : aiMode === true ? 'explain' : undefined;
    if (mode === 'explain') {
      findings = await applyExplain(findings, client, config.ai, sources);
    } else if (isInternalAi() && mode === 'triage') {
      findings = await applyTriage(findings, client, config.ai, sources);
    } else if (isInternalAi() && mode === 'logic') {
      findings = sortFindings([...findings, ...(await runLogicHunt(cwd, files, client))]);
    }
  }
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
    policy: policyResult,
  };
}

/** Public library API: scan with the built-in modules. */
export function scan(options: ScanOptions = {}): Promise<ScanResult> {
  return runScan(options);
}
