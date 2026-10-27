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
import { raise } from './raise.js';
import { partitionPerf2, perf2Enabled } from './perf2.js';
import { beginSharedAst, endSharedAst, preparseProject } from './shared-ast.js';
import { listStagedFiles } from './git.js';
import { budgetEnabled, armBudget, budgetSnapshot, clearBudget } from './budget.js';
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
import { modelsEnabled } from '../modules/sast/experimental.js';
import { applyModelSuppressions } from '../modules/sast/models.js';
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
  /** Phase 501. Requires FULLSHIELD_EXPERIMENTAL_DIFFSCAN=1. */
  diff?: boolean;
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
  /**
   * Phase 79. Seconds for `--max-time`. Applied only when
   * `FULLSHIELD_EXPERIMENTAL_BUDGET=1`.
   */
  maxTimeSeconds?: number;
  /** Phase 90. Overrides `semgrepRules` in config. The file is parsed only when the flag is on. */
  semgrepRules?: string;
}

export interface ScanMetadata {
  version: string;
  startedAt: string;
  durationMs: number;
  cwd: string;
  filesScanned: number;
  modulesRequested: readonly ModuleName[];
  /** Requested modules that are actually implemented and ran. */
  modulesRun: readonly ModuleName[];
  /** Set when `scan --history` stops at the commit cap. Exact text: `scanned N of M commits`. */
  history?: string;
  /** Phase 48. Direct dependencies no project file imports. Absent when the list is empty. */
  unusedDirect?: { packages: string[]; advisories: number };
  /** Phase 81. One line per model pack skipped because the installed version is out of range. */
  info?: string[];
  /** Phase 78. Present only when FULLSHIELD_EXPERIMENTAL_PERF2=1. Not findings. */
  skipped?: {
    total: number;
    oversize: number;
    minified: number;
    declaration: number;
    sourceMap: number;
    generated: number;
  };
  /**
   * Phase 79. Set only when `FULLSHIELD_EXPERIMENTAL_BUDGET` stops the scan early.
   * An incomplete scan is not a clean result.
   */
  incomplete?: true;
  /** Modules that did not finish. Deps, secrets, and config still run to completion. */
  incompleteModules?: ModuleName[];
  /** Source files that did not get a SAST taint pass. */
  filesNotTaintChecked?: number;
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
   * Phase 80 and Phase 81. Findings removed from `findings`.
   * Present when the type checker ran or a model pack suppressed a finding.
   */
  suppressed?: Finding[];
  /** Phase 80. Missing `typescript` (FS-E013) or the types.maxFiles fallback. Printed by the CLI. */
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
function armScanBudget(options: ScanOptions): void {
  if (
    budgetEnabled() &&
    options.maxTimeSeconds !== undefined &&
    Number.isFinite(options.maxTimeSeconds) &&
    options.maxTimeSeconds > 0
  ) {
    armBudget(options.maxTimeSeconds);
  }
}

async function requireScanDirectory(cwdOption: string | undefined): Promise<string> {
  const cwd = resolve(cwdOption ?? process.cwd());
  const stats = await stat(cwd).catch(() => null);
  if (stats === null || !stats.isDirectory()) {
    throw new Error(`scan path is not a directory: ${cwd}`);
  }
  return cwd;
}

interface LoadedScan {
  config: ResolvedConfig;
  loadedPolicy: FullShieldPolicy | undefined;
  modulesRequested: ModuleName[];
}

async function loadScanConfig(cwd: string, options: ScanOptions): Promise<LoadedScan> {
  let config = await loadConfig(cwd, options.configPath);
  if (options.semgrepRules !== undefined && options.semgrepRules.length > 0) {
    config = { ...config, semgrepRules: options.semgrepRules };
  }
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
  return { config, loadedPolicy, modulesRequested };
}

async function applyChangedFiles(cwd: string, options: ScanOptions, files: string[]): Promise<string[]> {
  const incrementalOn =
    options.experimentalIncremental === true || process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM === '1';
  if (!incrementalOn || (options.changed !== true && options.since === undefined && !options.changedFiles)) {
    return files;
  }
  const { resolveChangedFiles } = await import('../incremental/index.js');
  const listed =
    options.changedFiles ??
    resolveChangedFiles(cwd, {
      changed: options.changed,
      since: options.since,
      experimental: true,
    });
  if (listed.length === 0) {return files;}
  const allow = new Set(listed);
  return files.filter((file) => allow.has(file));
}

interface SelectedFiles {
  files: string[];
  skipped: ScanMetadata['skipped'];
}

async function selectScanFiles(cwd: string, options: ScanOptions, config: ResolvedConfig): Promise<SelectedFiles> {
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
  if (options.diff === true) {
    if (process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN !== '1') {
      raise('scan --diff requires FULLSHIELD_EXPERIMENTAL_DIFFSCAN=1');
    }
    const { limitToFrontier } = await import('../diffscan/frontier.js');
    files = await limitToFrontier(cwd, files);
  }
  files = await applyChangedFiles(cwd, options, files);
  let skipped: ScanMetadata['skipped'];
  if (perf2Enabled()) {
    const part = await partitionPerf2(cwd, files, config.sast.maxFileBytes);
    files = part.kept;
    skipped = part.skipped;
  }
  return { files, skipped };
}

interface Gathered {
  findings: Finding[];
  extraHits: SecretHit[];
  historyNotice: string | undefined;
  modulesRun: ModuleName[];
}

async function readModuleFindings(
  cwd: string,
  files: string[],
  loaded: LoadedScan,
  modules: readonly ScanModule[],
): Promise<{ findings: Finding[]; modulesRun: ModuleName[] }> {
  const available = new Map(modules.map((mod) => [mod.name, mod]));
  const modulesRun = loaded.modulesRequested.filter((name) => available.has(name));
  const ctx: ModuleContext = { cwd, files, config: loaded.config };
  beginSharedAst();
  try {
    await preparseProject(cwd, files, loaded.config.sast.maxFileBytes);
    const findings = await collectModuleFindings(available, modulesRun, ctx);
    return { findings, modulesRun };
  } finally {
    endSharedAst();
  }
}

async function addHistoryAndBundle(
  cwd: string,
  options: ScanOptions,
  secretsWanted: boolean,
  collected: Finding[],
): Promise<{ extraHits: SecretHit[]; historyNotice: string | undefined }> {
  const extraHits: SecretHit[] = [];
  let historyNotice: string | undefined;
  if (!secretsAdvEnabled() || !secretsWanted) {return { extraHits, historyNotice };}
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
  return { extraHits, historyNotice };
}

async function gatherFindings(
  cwd: string,
  options: ScanOptions,
  loaded: LoadedScan,
  files: string[],
  modules: readonly ScanModule[],
): Promise<Gathered> {
  const read = await readModuleFindings(cwd, files, loaded, modules);
  const collected = read.findings;
  if (options.diff === true && process.env.FULLSHIELD_EXPERIMENTAL_DIFFSCAN === '1') {
    const { carrierFindings } = await import('../diffscan/carrier.js');
    collected.push(...(await carrierFindings(cwd, files)));
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_MCPCFG === '1') {
    collected.push(
      ...scanMcpConfig(cwd, { experimental: true, includeHome: options.includeHome === true }),
    );
  }
  const extra = await addHistoryAndBundle(cwd, options, loaded.modulesRequested.includes('secrets'), collected);
  return { findings: collected, extraHits: extra.extraHits, historyNotice: extra.historyNotice, modulesRun: read.modulesRun };
}

async function sourceTexts(cwd: string, collected: readonly Finding[]): Promise<Record<string, string>> {
  const sources: Record<string, string> = {};
  for (const file of new Set(collected.map((f) => f.file).filter((f): f is string => f !== undefined))) {
    try {
      sources[file] = await readFile(join(cwd, file), 'utf8');
    } catch {
      // Finding file disappeared between walk and filter; keep the finding.
    }
  }
  return sources;
}

interface Baselined {
  findings: Finding[];
  suppressionErrors: string[];
  sources: Record<string, string>;
}

async function baselineFindings(
  cwd: string,
  config: ResolvedConfig,
  options: ScanOptions,
  collected: Finding[],
): Promise<Baselined> {
  const sources = await sourceTexts(cwd, collected);
  const unsuppressed = applyInlineSuppressions(dedupe(collected), sources);
  const baselinePath = resolve(cwd, config.baseline);
  if (options.updateBaseline === true) {
    await writeBaseline(baselinePath, unsuppressed);
  }
  const baselineDoc = await readBaseline(baselinePath);
  const suppressed = applySuppressions(sortFindings(applyBaseline(unsuppressed, baselineDoc)), baselineDoc?.suppressions);
  return { findings: sortFindings(suppressed.findings), suppressionErrors: suppressed.errors, sources };
}

async function cachedSource(
  cwd: string,
  file: string,
  sources: Record<string, string>,
): Promise<string | undefined> {
  const cached = sources[file];
  if (cached !== undefined) {return cached;}
  try {
    return await readFile(join(cwd, file), 'utf8');
  } catch {
    return undefined;
  }
}

async function verifyOwnedSecrets(
  findings: Finding[],
  extraHits: readonly SecretHit[],
  sources: Record<string, string>,
  cwd: string,
  options: ScanOptions,
): Promise<Finding[]> {
  const { applyVerification } = await import('../modules/secrets/verify.js');
  const { scanTextForSecretHits } = await import('../modules/secrets/index.js');
  const secretById = new Map<string, string>();
  for (const hit of extraHits) {
    if (hit.secret !== undefined) {secretById.set(hit.finding.id, hit.secret);}
  }
  for (const finding of findings) {
    if (finding.module !== 'secrets' || finding.file === undefined || secretById.has(finding.id)) {continue;}
    const text = await cachedSource(cwd, finding.file, sources);
    if (text === undefined) {continue;}
    for (const hit of scanTextForSecretHits(finding.file, text)) {
      if (hit.secret !== undefined) {secretById.set(hit.finding.id, hit.secret);}
    }
  }
  return sortFindings(await applyVerification(findings, secretById, { fetchImpl: options.verifyFetch }));
}

function secretsNeedVerify(options: ScanOptions, modulesRequested: readonly string[]): boolean {
  return (
    secretsAdvEnabled() &&
    modulesRequested.includes('secrets') &&
    options.verifySecrets === true &&
    options.iOwnTheseCredentials === true
  );
}

interface DecorateInput {
  cwd: string;
  files: readonly string[];
  loaded: LoadedScan;
  options: ScanOptions;
  sources: Record<string, string>;
  modulesRun: ModuleName[];
}

interface ScanTail {
  findings: Finding[];
  policyResult: PolicyScanResult | undefined;
  modelSuppressed: Finding[] | undefined;
  modelInfo: string[] | undefined;
  typeSuppressed: Finding[] | undefined;
  typesNotice: string | undefined;
  attackPaths: AttackPath[] | undefined;
}

function aiRequested(aiMode: ScanOptions['ai'], config: ResolvedConfig): boolean {
  return aiMode === true || aiMode === 'triage' || aiMode === 'explain' || aiMode === 'logic' || config.ai.enabled;
}

async function applyAiMode(findings: Finding[], input: DecorateInput): Promise<Finding[]> {
  const { options, loaded, sources, cwd, files } = input;
  if (!aiRequested(options.ai, loaded.config)) {return findings;}
  const client = createAiClient({
    enabled: true,
    config: { ...loaded.config.ai, enabled: true },
    useFixtures: !isLiveAi(),
  });
  const mode = typeof options.ai === 'string' ? options.ai : options.ai === true ? 'explain' : undefined;
  if (mode === 'explain') {return applyExplain(findings, client, loaded.config.ai, sources);}
  if (isInternalAi() && mode === 'triage') {return applyTriage(findings, client, loaded.config.ai, sources);}
  if (isInternalAi() && mode === 'logic') {
    return sortFindings([...findings, ...(await runLogicHunt(cwd, files, client))]);
  }
  return findings;
}

async function decorateFindings(findingsIn: Finding[], input: DecorateInput): Promise<ScanTail> {
  let findings = findingsIn;
  let policyResult: PolicyScanResult | undefined;
  if (input.loaded.loadedPolicy !== undefined) {
    const applied = applyPolicy(findings, input.loaded.loadedPolicy, {
      branch: input.options.policyBranch ?? resolvePolicyBranch(input.cwd),
      modulesRun: input.modulesRun,
    });
    findings = applied.findings;
    policyResult = {
      enabled: true,
      file: join(input.cwd, POLICY_FILE_NAME),
      failOn: applied.failOn,
      errors: applied.errors,
      policy: input.loaded.loadedPolicy,
    };
  }
  let modelSuppressed: Finding[] | undefined;
  let modelInfo: string[] | undefined;
  if (modelsEnabled()) {
    const applied = await applyModelSuppressions(input.cwd, findings);
    findings = sortFindings(applied.findings);
    if (applied.suppressed.length > 0) {modelSuppressed = applied.suppressed;}
    if (applied.info.length > 0) {modelInfo = applied.info;}
  }
  findings = applyPriority(await applyAiMode(findings, input));
  let typeSuppressed: Finding[] | undefined;
  let typesNotice: string | undefined;
  if (typesEnabled()) {
    const { applyTypeSuppression } = await import('../modules/sast/type-receivers.js');
    const applied = await applyTypeSuppression(findings, input.cwd, input.loaded.config.types);
    findings = applied.findings;
    typeSuppressed = applied.suppressed;
    typesNotice = applied.notice;
  }
  let attackPaths: AttackPath[] | undefined;
  if (input.options.paths === true && process.env.FULLSHIELD_EXPERIMENTAL_PATHS === '1') {
    const { buildAttackPathsFromFiles } = await import('../paths/index.js');
    attackPaths = await buildAttackPathsFromFiles(findings, input.cwd, input.files);
  }
  return { findings, policyResult, modelSuppressed, modelInfo, typeSuppressed, typesNotice, attackPaths };
}

function buildScanResult(input: {
  findings: Finding[];
  startedAt: string;
  t0: number;
  cwd: string;
  files: readonly string[];
  loaded: LoadedScan;
  selected: SelectedFiles;
  gathered: Gathered;
  baselined: Baselined;
  tail: ScanTail;
  modulesRun: ModuleName[];
}): ScanResult {
  const { findings, startedAt, t0, cwd, files, loaded, selected, gathered, baselined, tail, modulesRun } = input;
  return {
    findings,
    summary: summarize(findings),
    metadata: {
      version: packageVersion(),
      startedAt,
      durationMs: Math.round((performance.now() - t0) * 100) / 100,
      cwd,
      filesScanned: files.length,
      modulesRequested: [...loaded.modulesRequested],
      modulesRun,
      ...(gathered.historyNotice !== undefined ? { history: gathered.historyNotice } : {}),
      ...(selected.skipped !== undefined ? { skipped: selected.skipped } : {}),
      ...(depsModule.unusedDirect !== undefined ? { unusedDirect: depsModule.unusedDirect } : {}),
      ...(depsModule.upgradePlan !== undefined ? { upgradePlan: depsModule.upgradePlan } : {}),
      ...(budgetSnapshot() ?? {}),
      ...(tail.modelInfo !== undefined ? { info: tail.modelInfo } : {}),
    },
    config: loaded.config,
    policy: tail.policyResult,
    ...(baselined.suppressionErrors.length > 0 ? { suppressionErrors: baselined.suppressionErrors } : {}),
    ...(tail.typeSuppressed !== undefined || tail.modelSuppressed !== undefined
      ? { suppressed: [...(tail.modelSuppressed ?? []), ...(tail.typeSuppressed ?? [])] }
      : {}),
    ...(tail.typesNotice !== undefined ? { typesNotice: tail.typesNotice } : {}),
    ...(tail.attackPaths !== undefined ? { paths: tail.attackPaths } : {}),
  };
}

export async function runScan(
  options: ScanOptions = {},
  modules: readonly ScanModule[] = builtinModules,
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const t0 = performance.now();
  depsModule.unusedDirect = undefined;
  depsModule.upgradePlan = undefined;
  try {
    armScanBudget(options);
    const cwd = await requireScanDirectory(options.cwd);
    const loaded = await loadScanConfig(cwd, options);
    const selected = await selectScanFiles(cwd, options, loaded.config);
    const gathered = await gatherFindings(cwd, options, loaded, selected.files, modules);
    const baselined = await baselineFindings(cwd, loaded.config, options, gathered.findings);
    let findings = baselined.findings;
    if (secretsNeedVerify(options, loaded.modulesRequested)) {
      findings = await verifyOwnedSecrets(findings, gathered.extraHits, baselined.sources, cwd, options);
    }
    const tail = await decorateFindings(findings, {
      cwd,
      files: selected.files,
      loaded,
      options,
      sources: baselined.sources,
      modulesRun: gathered.modulesRun,
    });
    return buildScanResult({
      findings: tail.findings,
      startedAt,
      t0,
      cwd,
      files: selected.files,
      loaded,
      selected,
      gathered,
      baselined,
      tail,
      modulesRun: gathered.modulesRun,
    });
  } finally {
    clearBudget();
  }
}

/** Public library API: scan with the built-in modules. */
export function scan(options: ScanOptions = {}): Promise<ScanResult> {
  return runScan(options);
}
