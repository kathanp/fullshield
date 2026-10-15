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
import { phase29Rules } from './rules/phase29.js';
import type { AstNode, RuleContext, SastRule } from './types.js';
import { scanPromptInjection } from '../../ai/injection.js';

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
      functionHasPasswordName: (node) => factsFor(node, facts).hasPasswordName,
      assignedName: (node) => assignedNameOf(node),
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
    functionHasPasswordName: () => false,
    assignedName: () => undefined,
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

export const sastModule: ScanModule = {
  name: 'sast',
  async run(ctx) {
    const findings: Finding[] = [];
    const parsed: ParsedSource[] = [];
    for (const rel of ctx.files) {
      const isSource = SOURCE_EXT.test(rel);
      const isTemplate = TEMPLATE_EXT.test(rel);
      if (!isSource && !isTemplate) continue;
      let source: string;
      try {
        source = await readFile(join(ctx.cwd, rel), 'utf8');
      } catch {
        continue;
      }
      if (source.length > 1024 * 1024 || source.includes('\u0000')) continue;
      if (isTemplate) {
        findings.push(...findingsFromTemplate(rel, source));
        continue;
      }
      try {
        const ast = await parseSource(source);
        parsed.push({ file: rel, source, ast });
      } catch {
        // Unparseable file: skip. A scanner must not execute or crash on user code.
      }
    }
    const files = new Set(parsed.map((p) => p.file));
    const returning = new Map<string, Set<string>>();
    for (const p of parsed) {
      returning.set(p.file, functionsThatReturnTaint(p.ast));
    }
    for (const p of parsed) {
      const ns = collectRequires(p.file, p.ast, files);
      const extra = new Set<string>(returning.get(p.file));
      for (const [local, spec] of ns) {
        const hash = spec.indexOf('#');
        const file = hash >= 0 ? spec.slice(0, hash) : spec;
        const exp = hash >= 0 ? spec.slice(hash + 1) : local;
        if (returning.get(file)?.has(exp)) extra.add(local);
      }
      findings.push(...findingsFromAst(p.file, p.source, p.ast, extra));
    }
    findings.push(...runInterproc(parsed));
    return findings;
  },
};
