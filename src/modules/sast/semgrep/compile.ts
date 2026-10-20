import { parse } from '@typescript-eslint/typescript-estree';

import type { Severity } from '../../../core/finding.js';
import { attachParents, walk } from '../ast.js';
import type { AstNode } from '../types.js';

const ELLIPSIS = '__fs_ellipsis';
const META = /^__fs_m_([A-Za-z_][A-Za-z0-9_]*)$/;

const RULE_KEYS = new Set([
  'id',
  'languages',
  'severity',
  'message',
  'pattern',
  'pattern-either',
  'pattern-not',
  'pattern-inside',
  'mode',
  'pattern-sources',
  'pattern-sinks',
  'pattern-sanitizers',
]);

const PATTERN_TYPES = new Set([
  'Identifier',
  'Literal',
  'MemberExpression',
  'CallExpression',
  'NewExpression',
  'FunctionDeclaration',
  'BlockStatement',
  'ExpressionStatement',
  'TemplateLiteral',
]);

const SEVERITY_MAP: Record<string, Severity> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  CRITICAL: 'critical',
  ERROR: 'high',
  WARNING: 'medium',
  INFO: 'low',
};

/** Phase 57 fields plus the documented Semgrep subset. */
export interface CompiledSemgrepRule {
  id: string;
  severity: Severity;
  message: string;
  languages: Array<'javascript' | 'typescript'>;
  mode: 'search' | 'taint';
  pattern?: AstNode;
  patternEither: AstNode[];
  patternNot: AstNode[];
  patternInside: AstNode[];
  /** Taint mode only. Mapped onto the existing taint engine at match time. */
  sources: AstNode[];
  sinks: AstNode[];
  sanitizers: AstNode[];
}

export function unsupportedConstruct(construct: string, ruleId: string): Error {
  return new Error(`unsupported construct "${construct}" in rule "${ruleId}"`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function ruleIdOf(value: unknown): string {
  if (!isRecord(value)) return '(unknown)';
  return typeof value.id === 'string' && value.id.length > 0 ? value.id : '(unknown)';
}

function rewritePattern(source: string, ruleId: string): string {
  let out = '';
  const openers: string[] = [];
  let quote: '"' | "'" | '`' | null = null;
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i] ?? '';
    if (quote !== null) {
      out += ch;
      if (ch === '\\') {
        out += source[i + 1] ?? '';
        i += 1;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      out += ch;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') {
      openers.push(ch);
      out += ch;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      openers.pop();
      out += ch;
      continue;
    }
    if (ch === '$' && /[A-Za-z_]/.test(source[i + 1] ?? '')) {
      let j = i + 1;
      while (/[A-Za-z0-9_]/.test(source[j] ?? '')) j += 1;
      out += `__fs_m_${source.slice(i + 1, j)}`;
      i = j - 1;
      continue;
    }
    if (ch === '.' && source[i + 1] === '.' && source[i + 2] === '.') {
      if (openers[openers.length - 1] !== '(') throw unsupportedConstruct('...', ruleId);
      out += ELLIPSIS;
      i += 2;
      continue;
    }
    out += ch;
  }
  return out;
}

function parentOf(node: AstNode): AstNode | undefined {
  return (node as { parent?: AstNode }).parent;
}

function assertPattern(root: AstNode, ruleId: string): void {
  attachParents(root);
  walk(root, (node) => {
    if (node.type === 'Identifier' && node.name === ELLIPSIS) {
      const parent = parentOf(node);
      const args = parent?.type === 'CallExpression' || parent?.type === 'NewExpression' ? parent.arguments : undefined;
      if (args === undefined || !args.includes(node)) throw unsupportedConstruct('...', ruleId);
      return;
    }
    if (node.type === 'Identifier' && META.test(node.name)) return;
    if (!PATTERN_TYPES.has(node.type)) throw unsupportedConstruct(node.type, ruleId);
    if (node.type === 'TemplateLiteral' && node.expressions.length > 0) {
      throw unsupportedConstruct('template', ruleId);
    }
  });
}

export function compilePattern(source: string, ruleId: string): AstNode {
  if (source.trim().length === 0) throw unsupportedConstruct('pattern', ruleId);
  const rewritten = rewritePattern(source, ruleId);
  let ast: AstNode;
  try {
    ast = parse(rewritten, {
      loc: true,
      range: true,
      jsx: true,
      comment: false,
      errorOnUnknownASTType: false,
      errorOnTypeScriptSyntacticAndSemanticIssues: false,
    });
  } catch {
    throw unsupportedConstruct('pattern', ruleId);
  }
  if (ast.type !== 'Program' || ast.body.length !== 1) throw unsupportedConstruct('pattern', ruleId);
  const stmt = ast.body[0];
  if (stmt === undefined) throw unsupportedConstruct('pattern', ruleId);
  const root = stmt.type === 'ExpressionStatement' ? stmt.expression : stmt;
  assertPattern(root, ruleId);
  return root;
}

function compilePatternList(value: unknown, field: string, ruleId: string): AstNode[] {
  if (!Array.isArray(value) || value.length === 0) throw unsupportedConstruct(field, ruleId);
  return value.map((item) => {
    if (!isRecord(item)) throw unsupportedConstruct(field, ruleId);
    for (const key of Object.keys(item)) {
      if (key !== 'pattern') throw unsupportedConstruct(key, ruleId);
    }
    if (typeof item.pattern !== 'string') throw unsupportedConstruct(field, ruleId);
    return compilePattern(item.pattern, ruleId);
  });
}

function compileRule(value: unknown): CompiledSemgrepRule {
  const ruleId = ruleIdOf(value);
  if (!isRecord(value)) throw unsupportedConstruct('rule', ruleId);
  for (const key of Object.keys(value)) {
    if (!RULE_KEYS.has(key)) throw unsupportedConstruct(key, ruleId);
  }
  if (typeof value.id !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(value.id)) {
    throw unsupportedConstruct('id', ruleId);
  }
  if (typeof value.message !== 'string' || value.message.length === 0) {
    throw unsupportedConstruct('message', ruleId);
  }
  if (typeof value.severity !== 'string' || SEVERITY_MAP[value.severity] === undefined) {
    throw unsupportedConstruct('severity', ruleId);
  }
  if (!Array.isArray(value.languages) || value.languages.length === 0) {
    throw unsupportedConstruct('languages', ruleId);
  }
  const languages: Array<'javascript' | 'typescript'> = [];
  const rawLanguages: unknown[] = value.languages;
  for (const language of rawLanguages) {
    if (language === 'javascript' || language === 'typescript') {
      languages.push(language);
      continue;
    }
    throw unsupportedConstruct(typeof language === 'string' ? language : 'languages', ruleId);
  }
  const mode = value.mode;
  if (mode !== undefined && mode !== 'taint') throw unsupportedConstruct('mode', ruleId);
  const taint = mode === 'taint';
  if (taint) {
    for (const field of ['pattern', 'pattern-either', 'pattern-not', 'pattern-inside'] as const) {
      if (value[field] !== undefined) throw unsupportedConstruct(field, ruleId);
    }
  } else {
    for (const field of ['pattern-sources', 'pattern-sinks', 'pattern-sanitizers'] as const) {
      if (value[field] !== undefined) throw unsupportedConstruct(field, ruleId);
    }
  }
  const pattern = typeof value.pattern === 'string' ? compilePattern(value.pattern, ruleId) : undefined;
  if (value.pattern !== undefined && pattern === undefined) throw unsupportedConstruct('pattern', ruleId);
  const patternEither = value['pattern-either'] !== undefined ? compilePatternList(value['pattern-either'], 'pattern-either', ruleId) : [];
  const patternNot = typeof value['pattern-not'] === 'string' ? [compilePattern(value['pattern-not'], ruleId)] : [];
  if (value['pattern-not'] !== undefined && patternNot.length === 0) throw unsupportedConstruct('pattern-not', ruleId);
  const patternInside = typeof value['pattern-inside'] === 'string' ? [compilePattern(value['pattern-inside'], ruleId)] : [];
  if (value['pattern-inside'] !== undefined && patternInside.length === 0) {
    throw unsupportedConstruct('pattern-inside', ruleId);
  }
  const sources = taint ? compilePatternList(value['pattern-sources'], 'pattern-sources', ruleId) : [];
  const sinks = taint ? compilePatternList(value['pattern-sinks'], 'pattern-sinks', ruleId) : [];
  const sanitizers =
    taint && value['pattern-sanitizers'] !== undefined
      ? compilePatternList(value['pattern-sanitizers'], 'pattern-sanitizers', ruleId)
      : [];
  if (!taint && pattern === undefined && patternEither.length === 0) throw unsupportedConstruct('pattern', ruleId);
  return {
    id: value.id,
    severity: SEVERITY_MAP[value.severity] ?? 'high',
    message: value.message,
    languages,
    mode: taint ? 'taint' : 'search',
    ...(pattern !== undefined ? { pattern } : {}),
    patternEither,
    patternNot,
    patternInside,
    sources,
    sinks,
    sanitizers,
  };
}

/** Compile a parsed YAML document. Any bad rule rejects the whole document. */
export function compileSemgrepDocument(doc: unknown): CompiledSemgrepRule[] {
  if (!isRecord(doc)) throw unsupportedConstruct('rules', '(unknown)');
  for (const key of Object.keys(doc)) {
    if (key !== 'rules') throw unsupportedConstruct(key, '(unknown)');
  }
  if (!Array.isArray(doc.rules)) throw unsupportedConstruct('rules', '(unknown)');
  const errors: string[] = [];
  const compiled: CompiledSemgrepRule[] = [];
  for (const rule of doc.rules) {
    try {
      compiled.push(compileRule(rule));
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  if (errors.length > 0) throw new Error(errors.join('\n'));
  return compiled;
}
