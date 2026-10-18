import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';
import { assignedNameOf, walk } from './ast.js';
import { collectRequires, runInterproc, type ParsedSource } from './interproc.js';
import {
  analyzeFile,
  factsFor,
  functionsThatReturnTaint,
  nodeHoldsBuiltFilter,
  nodeIsNosqlSanitized,
  nodeIsPathSanitized,
  nodeIsRequestObject,
  nodeIsSanitizedFor,
  nodeIsTainted,
} from './taint.js';
import { authRule } from './rules/auth.js';
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
import { phase29Rules, sourceHasCsrfGuard } from './rules/phase29.js';
import type { AstNode, RuleContext, SastRule } from './types.js';
import { scanPromptInjection } from '../../ai/injection.js';
import { parsePoolEnabled, parseWithPool } from '../../core/parse-pool.js';

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
  if (node.range === undefined) return '';
  return source.slice(node.range[0], node.range[1]).replace(/\s+/g, ' ').trim().slice(0, 120);
}

export function findingsFromAst(
  filename: string,
  source: string,
  ast: AstNode,
  extraReturners: ReadonlySet<string> = new Set(),
  projectCsrfProtected = false,
): Finding[] {
  const facts = analyzeFile(ast, extraReturners);
  const findings: Finding[] = [];

  for (const rule of sastRules) {
    const ctx: RuleContext = {
      filename,
      source,
      report: ({ node, message, confidence }) => {
        const snippet = snippetOf(source, node);
        findings.push({
          id: makeFindingId(rule.meta.id, filename, `${node.loc?.start.line ?? 0}|${snippet}`),
          ruleId: rule.meta.id,
          module: 'sast',
          title: rule.meta.title,
          severity: rule.meta.severity,
          confidence: confidence ?? 'high',
          cwe: rule.meta.cwe,
          file: filename,
          line: node.loc?.start.line,
          column: node.loc?.start.column,
          snippet,
          message,
          remediation: `${rule.meta.title}. See ${rule.meta.docs}`,
          references: [rule.meta.docs, rule.meta.cwe],
        });
      },
      isTainted: (node) => nodeIsTainted(node, facts),
      isPathSanitized: (node) => nodeIsPathSanitized(node, facts),
      isSanitizedFor: (node, kind) => nodeIsSanitizedFor(node, facts, kind),
      isNosqlSanitized: (node) => nodeIsNosqlSanitized(node, facts),
      isRequestObject: (node) => nodeIsRequestObject(node, facts),
      holdsBuiltFilter: (node) => nodeHoldsBuiltFilter(node, facts),
      functionHasPasswordName: (node) => factsFor(node, facts).hasPasswordName,
      assignedName: (node) => assignedNameOf(node),
      projectCsrfProtected,
    };
    const visitors = rule.create(ctx);
    walk(ast, (node) => {
      visitors[node.type]?.(node);
    });
  }
  findings.push(...scanPromptInjection(filename, source));
  return findings;
}

function findingsFromTemplate(filename: string, source: string): Finding[] {
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
  return findings;
}

/** Parse and scan a single source string (used by unit tests). */
export async function runSastOnText(filename: string, source: string): Promise<Finding[]> {
  if (TEMPLATE_EXT.test(filename)) return findingsFromTemplate(filename, source);
  const ast = await parseSource(source);
  return findingsFromAst(filename, source, ast);
}

/** Same rule and sink line is one finding. The first report wins. */
export function dedupeSastSinks(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    if (finding.module !== 'sast' || finding.line === undefined) {
      out.push(finding);
      continue;
    }
    const key = `${finding.ruleId}\0${finding.file ?? ''}\0${finding.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
}

/** Repos above this source-file count are parsed one file at a time. */
export function sastStreamThreshold(): number {
  const raw = process.env.FULLSHIELD_SAST_STREAM_AT;
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1) return Math.floor(parsed);
  }
  return 4000;
}

function sastBatchSize(): number {
  const raw = process.env.FULLSHIELD_SAST_BATCH;
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1) return Math.floor(parsed);
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
  if (source.includes('\u0000')) return 'it contains NUL bytes';
  const bytes = Buffer.byteLength(source);
  if (bytes > maxBytes) return `${bytes} bytes exceeds the SAST parse limit of ${maxBytes} bytes`;
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
  if (value === null || typeof value !== 'object') return undefined;
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

async function parseCode(source: string): Promise<AstNode | undefined> {
  if (!parsePoolEnabled()) return parseInProcess(source);
  try {
    // The pool caches one object and later walks mutate parent links on it.
    // Hand the scanner a copy so the next scan cannot see a broken tree.
    const cloned = cloneAst((await parseWithPool([source]))[0]);
    if (cloned !== undefined) return cloned;
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
    if (returning.get(file)?.has(exp)) extra.add(local);
  }
  return extra;
}

async function runSastStreaming(ctx: Parameters<ScanModule['run']>[0]): Promise<Finding[]> {
  const maxBytes = ctx.config.sast.maxFileBytes;
  const findings: Finding[] = [];
  const returning = new Map<string, Set<string>>();
  const parseable: string[] = [];
  const fileSet = new Set<string>();
  let projectCsrf = false;

  for (const rel of ctx.files) {
    const isSource = SOURCE_EXT.test(rel);
    const isTemplate = TEMPLATE_EXT.test(rel);
    if (!isSource && !isTemplate) continue;
    const source = await readScanSource(ctx.cwd, rel);
    if (source === undefined) continue;
    const why = skipReason(source, maxBytes);
    if (why !== undefined) {
      findings.push(skipFinding(rel, `Skipped ${rel}: ${why}.`));
      continue;
    }
    if (sourceHasCsrfGuard(source)) projectCsrf = true;
    if (isTemplate) {
      findings.push(...findingsFromTemplate(rel, source));
      continue;
    }
    const ast = await parseCode(source);
    if (ast === undefined) continue;
    returning.set(rel, functionsThatReturnTaint(ast));
    parseable.push(rel);
    fileSet.add(rel);
  }

  for (const rel of parseable) {
    const source = await readScanSource(ctx.cwd, rel);
    if (source === undefined) continue;
    const ast = await parseCode(source);
    if (ast === undefined) continue;
    findings.push(
      ...findingsFromAst(rel, source, ast, extraReturners(rel, ast, fileSet, returning), projectCsrf),
    );
  }

  const batch = sastBatchSize();
  for (let i = 0; i < parseable.length; i += batch) {
    const parsed: ParsedSource[] = [];
    for (const rel of parseable.slice(i, i + batch)) {
      const source = await readScanSource(ctx.cwd, rel);
      if (source === undefined) continue;
      const ast = await parseCode(source);
      if (ast === undefined) continue;
      parsed.push({ file: rel, source, ast });
    }
    findings.push(...runInterproc(parsed));
    releaseParsed(parsed);
  }
  return dedupeSastSinks(findings);
}

export const sastModule: ScanModule = {
  name: 'sast',
  async run(ctx) {
    const candidates = ctx.files.filter((rel) => SOURCE_EXT.test(rel) || TEMPLATE_EXT.test(rel));
    if (candidates.length > sastStreamThreshold()) return runSastStreaming(ctx);

    const maxBytes = ctx.config.sast.maxFileBytes;
    const findings: Finding[] = [];
    const parsed: ParsedSource[] = [];
    for (const rel of candidates) {
      const source = await readScanSource(ctx.cwd, rel);
      if (source === undefined) continue;
      const why = skipReason(source, maxBytes);
      if (why !== undefined) {
        findings.push(skipFinding(rel, `Skipped ${rel}: ${why}.`));
        continue;
      }
      if (TEMPLATE_EXT.test(rel)) {
        findings.push(...findingsFromTemplate(rel, source));
        continue;
      }
      const ast = await parseCode(source);
      if (ast === undefined) continue;
      parsed.push({ file: rel, source, ast });
    }
    const files = new Set(parsed.map((p) => p.file));
    const projectCsrf = parsed.some((p) => sourceHasCsrfGuard(p.source));
    const returning = new Map<string, Set<string>>();
    for (const entry of parsed) {
      returning.set(entry.file, functionsThatReturnTaint(entry.ast));
    }
    for (const entry of parsed) {
      findings.push(
        ...findingsFromAst(
          entry.file,
          entry.source,
          entry.ast,
          extraReturners(entry.file, entry.ast, files, returning),
          projectCsrf,
        ),
      );
    }
    findings.push(...runInterproc(parsed));
    const out = dedupeSastSinks(findings);
    releaseParsed(parsed);
    return out;
  },
};
