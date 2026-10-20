import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { parse } from '@typescript-eslint/typescript-estree';

import { makeFindingId, type Finding } from '../../../core/finding.js';
import { attachParents } from '../ast.js';
import { analyzeFile } from '../taint.js';
import type { AstNode } from '../types.js';
import type { CompiledSemgrepRule } from './compile.js';
import { semgrepRulesEnabled } from './flag.js';
import { loadUserSemgrepRules } from './load.js';
import { searchHits, taintHits } from './match.js';

function languageOf(file: string): 'javascript' | 'typescript' | undefined {
  if (file.endsWith('.ts') || file.endsWith('.tsx') || file.endsWith('.mts') || file.endsWith('.cts')) {
    return 'typescript';
  }
  if (file.endsWith('.js') || file.endsWith('.jsx') || file.endsWith('.mjs') || file.endsWith('.cjs')) {
    return 'javascript';
  }
  return undefined;
}

function snippetOf(source: string, node: AstNode): string {
  if (node.range === undefined) return '';
  return source.slice(node.range[0], node.range[1]).replace(/\s+/g, ' ').trim().slice(0, 120);
}

function findingFor(rule: CompiledSemgrepRule, file: string, source: string, node: AstNode): Finding {
  const snippet = snippetOf(source, node);
  const ruleId = `CUSTOM-${rule.id}`;
  return {
    id: makeFindingId(ruleId, file, `${node.loc?.start.line ?? 0}|${snippet}`),
    ruleId,
    module: 'sast',
    title: rule.message,
    severity: rule.severity,
    confidence: 'medium',
    file,
    line: node.loc?.start.line,
    column: node.loc?.start.column,
    snippet,
    message: rule.message,
    remediation: 'User-supplied rule. Results may differ from Semgrep. See docs/semgrep-subset.md.',
    source: 'user-rule',
  };
}

function applyRule(
  rule: CompiledSemgrepRule,
  file: string,
  source: string,
  ast: AstNode,
  facts: WeakMap<AstNode, import('../taint.js').ScopeFacts> | undefined,
): Finding[] {
  const nodes =
    rule.mode === 'taint' && facts !== undefined ? taintHits(rule, ast, facts) : rule.mode === 'search' ? searchHits(rule, ast) : [];
  return nodes.map((node) => findingFor(rule, file, source, node));
}

async function scanFile(file: string, cwd: string, rules: readonly CompiledSemgrepRule[], maxFileBytes: number): Promise<Finding[]> {
  const language = languageOf(file);
  if (language === undefined) return [];
  const applicable = rules.filter((rule) => rule.languages.includes(language));
  if (applicable.length === 0) return [];
  let source: string;
  try {
    source = await readFile(resolve(cwd, file), 'utf8');
  } catch {
    return [];
  }
  if (Buffer.byteLength(source) > maxFileBytes) return [];
  let ast: AstNode;
  try {
    ast = parse(source, {
      loc: true,
      range: true,
      jsx: true,
      comment: false,
      errorOnUnknownASTType: false,
      errorOnTypeScriptSyntacticAndSemanticIssues: false,
    });
  } catch {
    return [];
  }
  const needsTaint = applicable.some((rule) => rule.mode === 'taint');
  const facts = needsTaint ? analyzeFile(ast) : undefined;
  if (!needsTaint) attachParents(ast);
  const findings: Finding[] = [];
  for (const rule of applicable) findings.push(...applyRule(rule, file, source, ast, facts));
  return findings;
}

/** Scan project files with already-enabled user rules. Flag-off returns before the rules file is read. */
export async function scanUserSemgrepRules(options: {
  cwd: string;
  files: readonly string[];
  rulesPath: string | undefined;
  maxFileBytes: number;
}): Promise<Finding[]> {
  if (!semgrepRulesEnabled() || options.rulesPath === undefined || options.rulesPath.length === 0) return [];
  const rules = await loadUserSemgrepRules(resolve(options.cwd, options.rulesPath), true);
  const findings: Finding[] = [];
  for (const file of options.files) {
    findings.push(...(await scanFile(file, options.cwd, rules, options.maxFileBytes)));
  }
  return findings;
}
