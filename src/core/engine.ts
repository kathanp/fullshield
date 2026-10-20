import { readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';

import { configModule } from '../modules/config/index.js';
import { depsModule } from '../modules/deps/index.js';
import { scanMcpConfig } from '../modules/mcp/index.js';
import { typesEnabled } from '../modules/sast/experimental.js';
import { sastModule } from '../modules/sast/index.js';
import { secretsModule } from '../modules/secrets/index.js';
import { secretsAdvEnabled } from '../modules/secrets/experimental.js';
import type { SecretHit } from '../modules/secrets/types.js';
import { applyExplain, applyTriage } from '../ai/triage.js';
import { runLogicHunt } from '../ai/logic.js';
import { createAiClient, isInternalAi, isLiveAi } from '../ai/provider.js';
import { applyBaseline, applySuppressions, readBaseline, writeBaseline } from './baseline.js';
import { loadConfig, type ResolvedConfig } from './config.js';
import { walkFiles } from './fileWalker.js';
import { partitionPerf2, perf2Enabled } from './perf2.js';
import { beginSharedAst, endSharedAst, preparseProject } from './shared-ast.js';
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
import { applyPriority } from '../priority/score.js';
import type { AttackPath } from '../paths/types.js';
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
  /** Phase 85: join existing findings into attack paths. Requires FULLSHIELD_EXPERIMENTAL_PATHS=1. */
  paths?: boolean;
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
  /** Set when `scan --history` stops at the commit cap. Exact text: `scanned N of M commits`. */
  history?: string;
  /** Phase 48. Direct dependencies no project file imports. Absent when the list is empty. */
  unusedDirect?: { packages: string[]; advisories: number };
  /** Phase 78. Present only when FULLSHIELD_EXPERIMENTAL_PERF2=1. Not findings. */
  skipped?: {
    total: number;
    oversize: number;
    minified: number;
    declaration: number;
    sourceMap: number;
    generated: number;
  };
  /** Phase 49. Direct version bumps taken from OSV `fixed` versions. Absent when there is nothing to say. */
  upgradePlan?: {
    bumps: Array<{ name: string; from: string; to: string; safe: boolean; findings: number }>;
    unresolved: string[];
    sentence: string;
  };
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
  /** Set when a baseline suppression is missing fields or has expired. */
  suppressionErrors?: string[];
  /**
   * Phase 80. Findings removed from `findings` because the receiver type is not a sink.
   * Present only when FULLSHIELD_EXPERIMENTAL_TYPES=1 and the checker ran.
   */
  suppressed?: Finding[];
  /** Phase 80. Missing `typescript` (FS-E012) or the types.maxFiles fallback. Printed by the CLI. */
  typesNotice?: string;
  /** Phase 85. Present only when scan paths were requested and FULLSHIELD_EXPERIMENTAL_PATHS=1. */
  paths?: AttackPath[];
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

async function collectModuleFindings(
  available: ReadonlyMap<ModuleName, ScanModule>,
  modulesRun: readonly ModuleName[],
  ctx: ModuleContext,
): Promise<Finding[]> {
  if (!perf2Enabled()) {
    const collected: Finding[] = [];
    for (const name of modulesRun) {
      const module = available.get(name);
      if (module !== undefined) collected.push(...(await module.run(ctx)));
    }
    return collected;
  }
  const runs = await Promise.all(
    modulesRun.map(async (name) => {
      const module = available.get(name);
      const findings = module === undefined ? [] : await module.run(ctx);
      findings.sort((a, b) => a.id.localeCompare(b.id));
      return { name, findings };
    }),
  );
  runs.sort((a, b) => a.name.localeCompare(b.name));
  return runs.flatMap((run) => run.findings);
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
  depsModule.unusedDirect = undefined;
  depsModule.upgradePlan = undefined;

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
  let files = await walkFiles({
    cwd,
    ignore: config.ignore,
    defaultExcludes: config.defaultExcludes,
    excludes: config.excludes,
  });
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

  let skipped: ScanMetadata['skipped'];
  if (perf2Enabled()) {
    const part = await partitionPerf2(cwd, files, config.sast.maxFileBytes);
    files = part.kept;
    skipped = part.skipped;
  }

  const available = new Map(modules.map((m) => [m.name, m]));
  const modulesRun = modulesRequested.filter((name) => available.has(name));

  const ctx: ModuleContext = { cwd, files, config };
  if (perf2Enabled()) {
    beginSharedAst();
    await preparseProject(cwd, files, config.sast.maxFileBytes);
  }
  let collected: Finding[];
  try {
    collected = await collectModuleFindings(available, modulesRun, ctx);
  } finally {
    if (perf2Enabled()) endSharedAst();
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_MCPCFG === '1') {
    collected.push(
      ...scanMcpConfig(cwd, { experimental: true, includeHome: options.includeHome === true }),
    );
  }

  const extraHits: SecretHit[] = [];
  let historyNotice: string | undefined;
  const secretsWanted = modulesRequested.includes('secrets');
  if (secretsAdvEnabled() && secretsWanted) {
    if (options.history === true) {
      const { scanGitHistory } = await import('../modules/secrets/history.js');
      const hist = await scanGitHistory(cwd);
      extraHits.push(...hist.hits);
      collected.push(...hist.findings);
      historyNotice = hist.history;
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
  const baselineDoc = await readBaseline(baselinePath);
  let findings = sortFindings(applyBaseline(unsuppressed, baselineDoc));
  const suppressed = applySuppressions(findings, baselineDoc?.suppressions);
  findings = sortFindings(suppressed.findings);
  const suppressionErrors = suppressed.errors;

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
  findings = applyPriority(findings);

  let typeSuppressed: Finding[] | undefined;
  let typesNotice: string | undefined;
  if (typesEnabled()) {
    const { applyTypeSuppression } = await import('../modules/sast/type-receivers.js');
    const applied = await applyTypeSuppression(findings, cwd, config.types);
    findings = applied.findings;
    typeSuppressed = applied.suppressed;
    typesNotice = applied.notice;
  }

  let attackPaths: AttackPath[] | undefined;
  if (options.paths === true && process.env.FULLSHIELD_EXPERIMENTAL_PATHS === '1') {
    const { buildAttackPathsFromFiles } = await import('../paths/index.js');
    attackPaths = await buildAttackPathsFromFiles(findings, cwd, files);
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
      ...(historyNotice !== undefined ? { history: historyNotice } : {}),
      ...(skipped !== undefined ? { skipped } : {}),
      ...(depsModule.unusedDirect !== undefined ? { unusedDirect: depsModule.unusedDirect } : {}),
      ...(depsModule.upgradePlan !== undefined ? { upgradePlan: depsModule.upgradePlan } : {}),
    },
    config,
    policy: policyResult,
    ...(suppressionErrors.length > 0 ? { suppressionErrors } : {}),
    ...(typeSuppressed !== undefined ? { suppressed: typeSuppressed } : {}),
    ...(typesNotice !== undefined ? { typesNotice } : {}),
    ...(attackPaths !== undefined ? { paths: attackPaths } : {}),
  };
}

/** Public library API: scan with the built-in modules. */
export function scan(options: ScanOptions = {}): Promise<ScanResult> {
  return runScan(options);
}
