import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';
import { assignedNameOf, attachParents, walk } from './ast.js';
import { crypto2Enabled, modelsEnabled, tlsEnabled, sstiEnabled, webhookEnabled, session2Enabled, logLeakEnabled, nextEnabled, browserEnabled, idorEnabled } from './experimental.js';
import { modelSinkFindings, resolveModelPacks, setActiveModels } from './models.js';
import { collectRequires, runInterproc, type ParsedSource } from './interproc.js';
import { crossFileReturnFindings } from './returns.js';
import { cachedReturners, setTaintSummaryConfig, taintSummariesEnabled } from './summaries.js';
import {
  analyzeFile,
  factsFor,
  functionsThatReturnTaint,
  nodeHoldsBuiltFilter,
  nodeIsNosqlSanitized,
  nodeIsPathSanitized,
  nodeIsRequestObject,
  nodeIsSanitizedFor,
  nodeIsSqlCleared,
  nodeIsTainted,
  setCustomTaint,
  type ScopeFacts,
} from './taint.js';
import { authRule, setAuthProject } from './rules/auth.js';
import { cmdiRule } from './rules/cmdi.js';
import { cryptoRule } from './rules/crypto.js';
import { evalRule } from './rules/eval.js';
import { jwtRule } from './rules/jwt.js';
import { nosqliRule } from './rules/nosqli.js';
import { pathRule } from './rules/path.js';
import { protoRule } from './rules/proto.js';
import { redirectRule } from './rules/redirect.js';
import { sqliRule } from './rules/sqli.js';
import { ssrfRule } from './rules/ssrf.js';
import { TEMPLATE_EXT, xssRule } from './rules/xss.js';
import { lineHasTracedSwig, mergeSwigViews, swigNamesForFile, taintedSwigViews, type SwigViewTaint } from './swig-render.js';
import { phase29Rules, sourceHasCsrfGuard } from './rules/phase29.js';
import { crypto2Rules } from './rules/crypto2.js';
import {
  clearBreadthProject,
  domRule,
  idorRule,
  isBrowserSource,
  logLeakRule,
  nextProjectFindings,
  nextServerRule,
  passportVersionFrom,
  postMessageRule,
  reactRule,
  scanBrowserMarkup,
  sessionRule,
  setBreadthProject,
  setBreadthSources,
  sstiRule,
  tokenStoreRule,
  webhookRule,
} from './rules/breadth.js';
import { scanTlsConfigText, tlsRules } from './rules/tls.js';
import type { AstNode, RuleContext, SastRule } from './types.js';
import { scanPromptInjection } from '../../ai/injection.js';
import { budgetArmed, budgetExpired, markTaintStopped } from '../../core/budget.js';
import { parsePoolEnabled, parseWithPool } from '../../core/parse-pool.js';
import { sharedAstActive, sharedParse } from '../../core/shared-ast.js';
import { clearTaintWalk, lazyTaintFiles } from './lazy-taint.js';
import { semgrepRulesEnabled } from './semgrep/flag.js';
import { scanUserSemgrepRules } from './semgrep/run.js';

export const sastRules: readonly SastRule[] = [
  sqliRule,
  cmdiRule,
  pathRule,
  evalRule,
  jwtRule,
  cryptoRule,
  nosqliRule,
  ssrfRule,
  redirectRule,
  protoRule,
  xssRule,
  authRule,
  ...phase29Rules,
];

const SOURCE_EXT = /\.[cm]?[jt]sx?$/;

/** Finish nothing further: the current file already returned. Deps, secrets, and config are not stopped here. */
function haltTaint(remaining: number): boolean {
  if (!budgetArmed() || !budgetExpired()) {return false;}
  markTaintStopped('sast', remaining);
  return true;
}

export async function parseSource(code: string): Promise<AstNode> {
  const { parse } = await import('@typescript-eslint/typescript-estree');
  return parse(code, {
    loc: true,
    range: true,
    comment: false,
    jsx: true,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  });
}

function snippetOf(source: string, node: AstNode): string {
  if (node.range === undefined) {return '';}
  return source.slice(node.range[0], node.range[1]).replace(/\s+/g, ' ').trim().slice(0, 120);
}

export type FindingsAstOptions = {
  extraReturners?: ReadonlySet<string>;
  projectCsrfProtected?: boolean;
  skipTaint?: boolean;
};

function scopeFacts(
  ast: AstNode,
  extraReturners: ReadonlySet<string>,
  skipTaint: boolean,
): WeakMap<AstNode, ScopeFacts> {
  if (!skipTaint) {return analyzeFile(ast, extraReturners);}
  // Parent links are required by non-taint rules (e.g. TLS medium for a NODE_ENV guard).
  attachParents(ast);
  return new WeakMap<AstNode, ScopeFacts>();
}

function rulesForFile(filename: string, source: string): SastRule[] {
  const browserFile = browserEnabled() && isBrowserSource(filename, source);
  const rules: SastRule[] = browserFile
    ? [domRule, reactRule, postMessageRule, tokenStoreRule]
    : [...sastRules];
  if (tlsEnabled()) {rules.push(...tlsRules);}
  if (crypto2Enabled()) {rules.push(...crypto2Rules);}
  if (browserFile) {return rules;}
  if (sstiEnabled()) {rules.push(sstiRule);}
  if (logLeakEnabled()) {rules.push(logLeakRule);}
  if (webhookEnabled()) {rules.push(webhookRule);}
  if (session2Enabled()) {rules.push(sessionRule);}
  if (idorEnabled()) {rules.push(idorRule);}
  if (nextEnabled()) {rules.push(nextServerRule);}
  return rules;
}

function ruleContext(
  filename: string,
  source: string,
  facts: WeakMap<AstNode, ScopeFacts>,
  findings: Finding[],
  opts: { rule: SastRule; projectCsrfProtected: boolean },
): RuleContext {
  const { rule, projectCsrfProtected } = opts;
  return {
    filename,
    source,
    report: ({ node, message, confidence, severity, context }) => {
      const snippet = snippetOf(source, node);
      findings.push({
        id: makeFindingId(rule.meta.id, filename, `${node.loc?.start.line ?? 0}|${snippet}`),
        ruleId: rule.meta.id,
        module: 'sast',
        title: rule.meta.title,
        severity: severity ?? rule.meta.severity,
        confidence: confidence ?? 'high',
        cwe: rule.meta.cwe,
        file: filename,
        line: node.loc?.start.line,
        column: node.loc?.start.column,
        snippet,
        message,
        remediation: `${rule.meta.title}. See ${rule.meta.docs}`,
        references: [rule.meta.docs, rule.meta.cwe],
        ...(context !== undefined ? { context } : {}),
        ...(rule.meta.id === 'SAST-IDOR-001' ? { source: 'rule' as const } : {}),
      });
    },
    isTainted: (node) => nodeIsTainted(node, facts),
    isSqlCleared: (node) => nodeIsSqlCleared(node, facts),
    isPathSanitized: (node) => nodeIsPathSanitized(node, facts),
    isSanitizedFor: (node, kind) => nodeIsSanitizedFor(node, facts, kind),
    isNosqlSanitized: (node) => nodeIsNosqlSanitized(node, facts),
    isRequestObject: (node) => nodeIsRequestObject(node, facts),
    holdsBuiltFilter: (node) => nodeHoldsBuiltFilter(node, facts),
    functionHasPasswordName: (node) => factsFor(node, facts).hasPasswordName,
    assignedName: (node) => assignedNameOf(node),
    projectCsrfProtected,
  };
}

export function findingsFromAst(
  filename: string,
  source: string,
  ast: AstNode,
  options: FindingsAstOptions = {},
): Finding[] {
  const extraReturners = options.extraReturners ?? new Set<string>();
  const facts = scopeFacts(ast, extraReturners, options.skipTaint === true);
  const findings: Finding[] = [];
  for (const rule of rulesForFile(filename, source)) {
    const visitors = rule.create(
      ruleContext(filename, source, facts, findings, {
        rule,
        projectCsrfProtected: options.projectCsrfProtected === true,
      }),
    );
    walk(ast, (node) => {
      visitors[node.type]?.(node);
    });
  }
  findings.push(...scanPromptInjection(filename, source));
  findings.push(...modelSinkFindings(filename, source, ast, (node) => nodeIsTainted(node, facts), findings));
  return findings;
}

function declaredViewEngine(source: string): string | undefined {
  // consolidate.swig / cons.swig registered for another extension, as NodeGoat does:
  // app.engine(".html", consolidate.swig); app.set("view engine", "html");
  if (/\.engine\(\s*['"]\.?[A-Za-z0-9_-]+['"]\s*,\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.swig\b/.test(source)) {
    return 'swig';
  }
  if (/\.engine\(\s*['"]\.?swig['"]/.test(source)) {return 'swig';}
  const set = /set\(\s*['"]view engine['"]\s*,\s*['"]\.?([A-Za-z0-9_-]+)['"]\s*\)/.exec(source);
  if (set?.[1]?.toLowerCase() === 'swig') {return 'swig';}
  const named = /\.engine\(\s*['"]\.?([A-Za-z0-9_-]+)['"]/.exec(source);
  const name = named?.[1]?.toLowerCase();
  if (name === 'swig') {return 'swig';}
  if (set?.[1] !== undefined && set[1].toLowerCase() !== 'html') {return set[1].toLowerCase();}
  if (name !== undefined && name !== 'html') {return name;}
  return undefined;
}

async function projectViewEngine(ctx: Parameters<ScanModule['run']>[0]): Promise<string | undefined> {
  for (const rel of ctx.files) {
    if (!SOURCE_EXT.test(rel)) {continue;}
    const source = await readScanSource(ctx.cwd, rel);
    const engine = source === undefined ? undefined : declaredViewEngine(source);
    if (engine !== undefined) {return engine;}
  }
  return undefined;
}

function findingsFromTemplate(
  filename: string,
  source: string,
  engine?: string,
  swigViews?: ReadonlyMap<string, SwigViewTaint>,
): Finding[] {
  const findings: Finding[] = [];
  const ctx: RuleContext = {
    filename,
    source,
    report: ({ node, message }) => {
      const snippet = source.split(/\r?\n/)[(node.loc?.start.line ?? 1) - 1]?.trim().slice(0, 120) ?? '';
      findings.push({
        id: makeFindingId(xssRule.meta.id, filename, `${node.loc?.start.line ?? 0}|${snippet}`),
        ruleId: xssRule.meta.id,
        module: 'sast',
        title: xssRule.meta.title,
        severity: xssRule.meta.severity,
        confidence: 'high',
        cwe: xssRule.meta.cwe,
        file: filename,
        line: node.loc?.start.line,
        column: node.loc?.start.column,
        snippet,
        message,
        remediation: `${xssRule.meta.title}. See ${xssRule.meta.docs}`,
        references: [xssRule.meta.docs, xssRule.meta.cwe],
      });
    },
    isTainted: () => false,
    isSqlCleared: () => false,
    isPathSanitized: () => false,
    isSanitizedFor: () => false,
    isNosqlSanitized: () => false,
    isRequestObject: () => false,
    holdsBuiltFilter: () => false,
    functionHasPasswordName: () => false,
    assignedName: () => undefined,
    projectCsrfProtected: false,
  };
  xssRule.create(ctx);
  if (engine === 'swig' && swigViews !== undefined) {
    const traced = swigNamesForFile(filename, swigViews);
    source.split(/\r?\n/).forEach((line, index) => {
      if (traced === undefined || !lineHasTracedSwig(line, traced)) {return;}
      ctx.report({
        node: {
          type: 'Literal',
          value: '',
          raw: "''",
          loc: { start: { line: index + 1, column: 0 }, end: { line: index + 1, column: 0 } },
          range: [0, 0],
        } as AstNode,
        message: 'Swig {{ }} is unescaped and can produce XSS.',
      });
    });
  }
  return findings;
}

/** Parse and scan a single source string (used by unit tests). */
export async function runSastOnText(filename: string, source: string): Promise<Finding[]> {
  if (TEMPLATE_EXT.test(filename)) {return findingsFromTemplate(filename, source);}
  const ast = await parseSource(source);
  return findingsFromAst(filename, source, ast);
}

/** Same rule and sink line is one finding. The first report wins, except a later cross-file return trace is kept when the first report has none. */
export function dedupeSastSinks(findings: readonly Finding[]): Finding[] {
  const seen = new Map<string, number>();
  const out: Finding[] = [];
  for (const finding of findings) {
    if (finding.module !== 'sast' || finding.line === undefined) {
      out.push(finding);
      continue;
    }
    const key = `${finding.ruleId}\0${finding.file ?? ''}\0${finding.line}`;
    const at = seen.get(key);
    if (at === undefined) {
      seen.set(key, out.length);
      out.push(finding);
      continue;
    }
    const prev = out[at];
    const crossFile = finding.trace?.some((step) => step.note?.startsWith('returned from')) === true;
    if (prev !== undefined && crossFile && (prev.trace === undefined || prev.trace.length === 0)) {
      out[at] = { ...prev, trace: finding.trace };
    }
  }
  return out;
}

/** Repos above this source-file count are parsed one file at a time. */
export function sastStreamThreshold(): number {
  const raw = process.env.FULLSHIELD_SAST_STREAM_AT;
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1) {return Math.floor(parsed);}
  }
  return 4000;
}

function sastBatchSize(): number {
  const raw = process.env.FULLSHIELD_SAST_BATCH;
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1) {return Math.floor(parsed);}
  }
  return 150;
}

function skipFinding(rel: string, message: string): Finding {
  return {
    id: makeFindingId('SAST-SKIP-001', rel, message),
    ruleId: 'SAST-SKIP-001',
    module: 'sast',
    title: 'File skipped by SAST',
    severity: 'info',
    confidence: 'high',
    file: rel,
    message,
    remediation:
      'Raise sast.maxFileBytes in fullshield.config.json to parse this file, or leave it skipped.',
  };
}

function skipReason(source: string, maxBytes: number): string | undefined {
  if (source.includes('\u0000')) {return 'it contains NUL bytes';}
  const bytes = Buffer.byteLength(source);
  if (bytes > maxBytes) {return `${bytes} bytes exceeds the SAST parse limit of ${maxBytes} bytes`;}
  return undefined;
}

async function readScanSource(cwd: string, rel: string): Promise<string | undefined> {
  try {
    return await readFile(join(cwd, rel), 'utf8');
  } catch {
    return undefined;
  }
}

function cloneAst(value: unknown): AstNode | undefined {
  if (value === null || typeof value !== 'object') {return undefined;}
  try {
    return structuredClone(value) as AstNode;
  } catch {
    return undefined;
  }
}

async function parseInProcess(source: string): Promise<AstNode | undefined> {
  try {
    return await parseSource(source);
  } catch {
    return undefined;
  }
}

async function parseCode(source: string, file?: string): Promise<AstNode | undefined> {
  if (file !== undefined && sharedAstActive()) {return sharedParse(file, source);}
  if (!parsePoolEnabled()) {return parseInProcess(source);}
  try {
    // The pool caches one object and later walks mutate parent links on it.
    // Hand the scanner a copy so the next scan cannot see a broken tree.
    const cloned = cloneAst((await parseWithPool([source]))[0]);
    if (cloned !== undefined) {return cloned;}
  } catch {
    // A dead worker used to become "no AST" and the file vanished from taint.
  }
  return parseInProcess(source);
}

function releaseParsed(parsed: ParsedSource[]): void {
  for (const entry of parsed) {
    entry.source = '';
    (entry as { ast?: AstNode }).ast = undefined;
  }
  parsed.length = 0;
}

function extraReturners(
  rel: string,
  ast: AstNode,
  files: ReadonlySet<string>,
  returning: ReadonlyMap<string, ReadonlySet<string>>,
): Set<string> {
  const ns = collectRequires(rel, ast, files);
  const extra = new Set<string>(returning.get(rel));
  for (const [local, spec] of ns) {
    const hash = spec.indexOf('#');
    const file = hash >= 0 ? spec.slice(0, hash) : spec;
    const exp = hash >= 0 ? spec.slice(hash + 1) : local;
    if (returning.get(file)?.has(exp)) {extra.add(local);}
  }
  return extra;
}

type StreamingLoad = {
  findings: Finding[];
  parseable: string[];
  fileSet: Set<string>;
  templates: { rel: string; source: string }[];
  swigViews: Map<string, SwigViewTaint>;
  lazyEntries: { file: string; source: string }[];
  projectCsrf: boolean;
  viewEngine: string | undefined;
};

async function loadStreamingInputs(ctx: Parameters<ScanModule['run']>[0]): Promise<StreamingLoad> {
  const maxBytes = ctx.config.sast.maxFileBytes;
  const viewEngine = await projectViewEngine(ctx);
  const load: StreamingLoad = {
    findings: [],
    parseable: [],
    fileSet: new Set(),
    templates: [],
    swigViews: new Map(),
    lazyEntries: [],
    projectCsrf: false,
    viewEngine,
  };
  for (const rel of ctx.files) {
    const isSource = SOURCE_EXT.test(rel);
    const isTemplate = TEMPLATE_EXT.test(rel) || (viewEngine === 'swig' && /\.(swig|html)$/.test(rel));
    if (!isSource && !isTemplate) {continue;}
    const source = await readScanSource(ctx.cwd, rel);
    if (source === undefined) {continue;}
    const why = skipReason(source, maxBytes);
    if (why !== undefined) {
      load.findings.push(skipFinding(rel, `Skipped ${rel}: ${why}.`));
      continue;
    }
    if (sourceHasCsrfGuard(source)) {load.projectCsrf = true;}
    if (isTemplate) {
      load.templates.push({ rel, source });
      continue;
    }
    const ast = await parseCode(source, rel);
    if (ast === undefined) {continue;}
    if (viewEngine === 'swig') {mergeSwigViews(load.swigViews, taintedSwigViews([{ ast }]));}
    load.parseable.push(rel);
    load.fileSet.add(rel);
    load.lazyEntries.push({ file: rel, source });
  }
  return load;
}

async function scanStreamingFiles(
  ctx: Parameters<ScanModule['run']>[0],
  load: StreamingLoad,
  walked: ReadonlySet<string>,
  returning: Map<string, Set<string>>,
): Promise<boolean> {
  let taintStopped = false;
  for (let index = 0; index < load.parseable.length; index += 1) {
    if (haltTaint(load.parseable.length - index)) {
      taintStopped = true;
      break;
    }
    const rel = load.parseable[index];
    if (rel === undefined) {continue;}
    const source = await readScanSource(ctx.cwd, rel);
    if (source === undefined) {continue;}
    const ast = await parseCode(source, rel);
    if (ast === undefined) {continue;}
    const skip = !walked.has(rel);
    if (!skip && !returning.has(rel)) {
      returning.set(rel, taintSummariesEnabled() ? cachedReturners(source, ast) : functionsThatReturnTaint(ast));
    }
    load.findings.push(
      ...findingsFromAst(rel, source, ast, {
        extraReturners: extraReturners(rel, ast, load.fileSet, returning),
        projectCsrfProtected: load.projectCsrf,
        skipTaint: skip,
      }),
    );
  }
  return taintStopped;
}

async function runSastStreaming(ctx: Parameters<ScanModule['run']>[0]): Promise<Finding[]> {
  if (haltTaint(ctx.files.filter((rel) => SOURCE_EXT.test(rel)).length)) {return [];}
  const load = await loadStreamingInputs(ctx);
  const walked = lazyTaintFiles(load.lazyEntries);
  const returning = new Map<string, Set<string>>();
  for (const rel of load.parseable) {
    if (!walked.has(rel)) {continue;}
    const source = await readScanSource(ctx.cwd, rel);
    if (source === undefined) {continue;}
    const ast = await parseCode(source, rel);
    if (ast === undefined) {continue;}
    returning.set(rel, taintSummariesEnabled() ? cachedReturners(source, ast) : functionsThatReturnTaint(ast));
  }
  let taintStopped = await scanStreamingFiles(ctx, load, walked, returning);
  if (!taintStopped && haltTaint(0)) {taintStopped = true;}
  if (!taintStopped) {
    await appendStreamingInterproc(ctx, load.parseable, walked, load.findings);
  }
  for (const template of load.templates) {
    load.findings.push(...findingsFromTemplate(template.rel, template.source, load.viewEngine, load.swigViews));
  }
  return dedupeSastSinks(load.findings);
}

async function appendStreamingInterproc(
  ctx: Parameters<ScanModule['run']>[0],
  parseable: readonly string[],
  walked: ReadonlySet<string>,
  findings: Finding[],
): Promise<void> {
  const batch = sastBatchSize();
  for (let i = 0; i < parseable.length; i += batch) {
    const parsed: ParsedSource[] = [];
    for (const rel of parseable.slice(i, i + batch)) {
      if (!walked.has(rel)) {continue;}
      const source = await readScanSource(ctx.cwd, rel);
      if (source === undefined) {continue;}
      const ast = await parseCode(source, rel);
      if (ast === undefined) {continue;}
      parsed.push({ file: rel, source, ast });
    }
    findings.push(...runInterproc(parsed));
    findings.push(...crossFileReturnFindings(parsed));
    releaseParsed(parsed);
  }
}

async function withUserSemgrep(ctx: Parameters<ScanModule['run']>[0], findings: Finding[]): Promise<Finding[]> {
  let out = findings;
  if (semgrepRulesEnabled() && ctx.config.semgrepRules !== undefined) {
    const extra = await scanUserSemgrepRules({
      cwd: ctx.cwd,
      files: ctx.files,
      rulesPath: ctx.config.semgrepRules,
      maxFileBytes: ctx.config.sast.maxFileBytes,
    });
    if (extra.length > 0) {out = [...out, ...extra];}
  }
  if (tlsEnabled()) {
    for (const rel of ctx.files) {
      if (SOURCE_EXT.test(rel)) {continue;}
      const source = await readScanSource(ctx.cwd, rel);
      if (source === undefined) {continue;}
      out = [...out, ...scanTlsConfigText(rel, source)];
    }
  }
  if (browserEnabled()) {
    for (const rel of ctx.files) {
      if (!/\.(vue|svelte)$/.test(rel)) {continue;}
      const source = await readScanSource(ctx.cwd, rel);
      if (source === undefined) {continue;}
      out = [...out, ...scanBrowserMarkup(rel, source)];
    }
  }
  if (nextEnabled()) {
    const texts: Array<{ file: string; source: string }> = [];
    for (const rel of ctx.files) {
      const source = await readScanSource(ctx.cwd, rel);
      if (source !== undefined) {texts.push({ file: rel, source });}
    }
    out = [...out, ...nextProjectFindings(texts)];
  }
  return out;
}

async function loadBreadthProject(cwd: string): Promise<void> {
  let passportVersion: string | undefined;
  let packageBrowser = false;
  try {
    const pkg = JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8')) as { browser?: unknown };
    packageBrowser = pkg.browser !== undefined;
  } catch {
    packageBrowser = false;
  }
  for (const name of ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']) {
    try {
      const version = passportVersionFrom(await readFile(join(cwd, name), 'utf8'));
      if (version !== undefined) {passportVersion = version;}
    } catch {
      continue;
    }
  }
  setBreadthProject({
    ...(passportVersion !== undefined ? { passportVersion } : {}),
    packageBrowser,
  });
}

function applyCustomSanitizers(ctx: Parameters<ScanModule['run']>[0]): void {
  if (process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS !== '1') {
    setCustomTaint(undefined);
    return;
  }
  const sources = new Set((ctx.config.sast.sources ?? []).map((row) => row.callee));
  const sanitizers = new Map<string, Set<string>>();
  for (const row of ctx.config.sast.sanitizers ?? []) {
    const classes = sanitizers.get(row.callee) ?? new Set<string>();
    for (const name of row.clears) {classes.add(name);}
    sanitizers.set(row.callee, classes);
  }
  setCustomTaint({ sources, sanitizers });
}

function returnersFor(entry: ParsedSource): Set<string> {
  return taintSummariesEnabled() ? cachedReturners(entry.source, entry.ast) : functionsThatReturnTaint(entry.ast);
}

async function collectBatchParsed(
  ctx: Parameters<ScanModule['run']>[0],
  viewEngine: string | undefined,
  candidates: readonly string[],
  findings: Finding[],
): Promise<{ parsed: ParsedSource[]; templates: { rel: string; source: string }[] }> {
  const maxBytes = ctx.config.sast.maxFileBytes;
  const parsed: ParsedSource[] = [];
  const templates: { rel: string; source: string }[] = [];
  for (const rel of candidates) {
    const source = await readScanSource(ctx.cwd, rel);
    if (source === undefined) {continue;}
    const why = skipReason(source, maxBytes);
    if (why !== undefined) {
      findings.push(skipFinding(rel, `Skipped ${rel}: ${why}.`));
      continue;
    }
    if (TEMPLATE_EXT.test(rel) || (viewEngine === 'swig' && /\.(swig|html)$/.test(rel))) {
      templates.push({ rel, source });
      continue;
    }
    const ast = await parseCode(source, rel);
    if (ast === undefined) {continue;}
    parsed.push({ file: rel, source, ast });
  }
  return { parsed, templates };
}

function appendBatchFindings(
  parsed: readonly ParsedSource[],
  walked: ReadonlySet<string>,
  returning: Map<string, Set<string>>,
  projectCsrf: boolean,
  findings: Finding[],
): boolean {
  const files = new Set(parsed.map((p) => p.file));
  let taintStopped = false;
  for (let index = 0; index < parsed.length; index += 1) {
    if (haltTaint(parsed.length - index)) {
      taintStopped = true;
      break;
    }
    const entry = parsed[index];
    if (entry === undefined) {continue;}
    findings.push(
      ...findingsFromAst(entry.file, entry.source, entry.ast, {
        extraReturners: extraReturners(entry.file, entry.ast, files, returning),
        projectCsrfProtected: projectCsrf,
        skipTaint: !walked.has(entry.file),
      }),
    );
  }
  return taintStopped;
}

async function runSastBatch(
  ctx: Parameters<ScanModule['run']>[0],
  viewEngine: string | undefined,
  candidates: readonly string[],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const { parsed, templates } = await collectBatchParsed(ctx, viewEngine, candidates, findings);
  const walked = lazyTaintFiles(parsed);
  const projectCsrf = parsed.some((p) => sourceHasCsrfGuard(p.source));
  const returning = new Map<string, Set<string>>();
  for (const entry of parsed) {
    if (!walked.has(entry.file)) {continue;}
    returning.set(entry.file, returnersFor(entry));
  }
  setAuthProject(new Map(parsed.map((entry) => [entry.file, entry.ast])));
  setBreadthSources(new Map(parsed.map((entry) => [entry.file, entry.source])));
  let taintStopped = appendBatchFindings(parsed, walked, returning, projectCsrf, findings);
  if (!taintStopped && haltTaint(0)) {taintStopped = true;}
  if (!taintStopped) {
    const interprocInput = parsed.filter((entry) => walked.has(entry.file));
    findings.push(...runInterproc(interprocInput));
    findings.push(...crossFileReturnFindings(interprocInput));
  }
  const swigViews = viewEngine === 'swig' ? taintedSwigViews(parsed) : undefined;
  for (const template of templates) {
    findings.push(...findingsFromTemplate(template.rel, template.source, viewEngine, swigViews));
  }
  const out = dedupeSastSinks(findings);
  releaseParsed(parsed);
  return out;
}

export const sastModule: ScanModule = {
  name: 'sast',
  async run(ctx) {
    applyCustomSanitizers(ctx);
    setTaintSummaryConfig(taintSummariesEnabled() ? ctx.config : undefined);
    clearTaintWalk();
    setActiveModels(modelsEnabled() ? resolveModelPacks(ctx.cwd).active : undefined);
    try {
      await loadBreadthProject(ctx.cwd);
      const viewEngine = await projectViewEngine(ctx);
      const candidates = ctx.files.filter(
        (rel) => SOURCE_EXT.test(rel) || TEMPLATE_EXT.test(rel) || (viewEngine === 'swig' && /\.(swig|html)$/.test(rel)),
      );
      if (candidates.length > sastStreamThreshold()) {
        return await withUserSemgrep(ctx, await runSastStreaming(ctx));
      }
      if (haltTaint(candidates.filter((rel) => SOURCE_EXT.test(rel)).length)) {return [];}
      return await withUserSemgrep(ctx, await runSastBatch(ctx, viewEngine, candidates));
    } finally {
      setCustomTaint(undefined);
      setTaintSummaryConfig(undefined);
      setAuthProject(undefined);
      setActiveModels(undefined);
      clearBreadthProject();
    }
  },
};
