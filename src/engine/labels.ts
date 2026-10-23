import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

/** Phase 256. Per-class taint labels. Flag off: this query reports nothing. */
export const LABEL_FLAG = 'FULLSHIELD_EXPERIMENTAL_LABELS';

export const SINK_LABELS = [
  'sqli',
  'nosqli',
  'cmdi',
  'path',
  'xss',
  'ssrf',
  'redirect',
  'eval',
  'ssti',
  'log',
] as const;

export type SinkLabel = (typeof SINK_LABELS)[number];

const STRING_INJECTION: readonly string[] = SINK_LABELS;

export interface SanitizerRow {
  name: string;
  removes: readonly string[];
}

/** Section 6.2 sanitizers as data. Thirty rows. `removes: []` clears nothing. */
export const SANITIZERS: readonly SanitizerRow[] = [
  { name: 'encodeURIComponent', removes: ['redirect', 'ssrf-path'] },
  { name: 'encodeURI', removes: ['redirect', 'ssrf-path'] },
  { name: 'DOMPurify', removes: ['xss'] },
  { name: 'sanitize-html', removes: ['xss'] },
  { name: 'he.escape', removes: ['xss'] },
  { name: 'escapeHtml', removes: ['xss'] },
  { name: 'validator.escape', removes: ['xss'] },
  { name: '_.escape', removes: ['xss'] },
  { name: 'htmlEntities.encode', removes: ['xss'] },
  { name: 'filterXSS', removes: ['xss'] },
  { name: 'parameterizedQuery', removes: ['sqli'] },
  { name: 'sqlstring.escape', removes: ['sqli'] },
  { name: 'mongoSanitize', removes: ['nosqli'] },
  { name: 'shellQuote', removes: ['cmdi'] },
  { name: 'pathBaseSep', removes: ['path'] },
  { name: 'Number', removes: STRING_INJECTION },
  { name: 'isInt', removes: STRING_INJECTION },
  { name: 'z.number', removes: STRING_INJECTION },
  { name: 'validator.isUUID', removes: STRING_INJECTION },
  { name: 'validator.isAlphanumeric', removes: STRING_INJECTION },
  { name: 'validator.isNumeric', removes: STRING_INJECTION },
  { name: 'z.enum', removes: STRING_INJECTION },
  { name: 'allowlist', removes: STRING_INJECTION },
  { name: 'JSON.parse', removes: [] },
  { name: 'parse', removes: [] },
  { name: 'z.string', removes: [] },
  { name: 'path.normalize', removes: [] },
  { name: 'path.basename', removes: [] },
  { name: 'decodeURIComponent', removes: [] },
  { name: 'toLowerCase', removes: [] },
];

export function labelsEnabled(): boolean {
  return process.env[LABEL_FLAG] === '1';
}

export function sourceLabels(): Set<string> {
  return new Set(SINK_LABELS);
}

export function applySanitizer(labels: ReadonlySet<string>, name: string): Set<string> {
  const next = new Set(labels);
  const row = SANITIZERS.find((item) => item.name === name);
  if (row === undefined) {return next;}
  for (const label of row.removes) {next.delete(label);}
  return next;
}

export function reachesSink(sanitizerName: string, sink: string, start?: ReadonlySet<string>): boolean {
  const labels = applySanitizer(start ?? sourceLabels(), sanitizerName);
  return labels.has(sink);
}

function slice(source: string, node: TSESTree.Node): string {
  const range = node.range;
  if (range === undefined) {return '';}
  return source.slice(range[0], range[1]);
}

const IDENT_SANITIZERS = new Set(['Number', 'isInt', 'escapeHtml', 'shellQuote', 'mongoSanitize', 'allowlist', 'parse']);

function identifierCalleeSanitizer(name: string): string | undefined {
  if (IDENT_SANITIZERS.has(name)) {return name;}
  return undefined;
}

function namedMemberSanitizer(property: string, objectText: string): string | undefined {
  if (property === 'sanitize' && objectText.includes('DOMPurify')) {return 'DOMPurify';}
  if (property === 'escape' && objectText.includes('validator')) {return 'validator.escape';}
  if (property === 'escape') {return 'he.escape';}
  if (property === 'parse' && /z\.number|zod\.number/.test(objectText)) {return 'z.number';}
  if (property === 'parse' && objectText === 'JSON') {return 'JSON.parse';}
  if (property === 'parse' && /\.string\(/.test(objectText)) {return 'z.string';}
  return undefined;
}

function skipsEncodeUri(callee: TSESTree.MemberExpression): boolean {
  return callee.object.type === 'Identifier' && callee.object.name === 'encodeURIComponent';
}

function memberSanitizerName(source: string, callee: TSESTree.MemberExpression): string | undefined {
  if (callee.property.type !== 'Identifier') {return undefined;}
  const property = callee.property.name;
  const named = namedMemberSanitizer(property, slice(source, callee.object));
  if (named !== undefined) {return named;}
  if (skipsEncodeUri(callee)) {return undefined;}
  if (property === 'encodeURIComponent') {return 'encodeURIComponent';}
  return undefined;
}

function sanitizerName(source: string, node: TSESTree.CallExpression): string | undefined {
  const callee = node.callee;
  if (callee.type === 'Identifier') {return identifierCalleeSanitizer(callee.name);}
  if (callee.type !== 'MemberExpression') {return undefined;}
  return memberSanitizerName(source, callee);
}

function identifierSanitizer(name: string): string | undefined {
  if (name === 'encodeURIComponent' || name === 'encodeURI' || name === 'decodeURIComponent') {return name;}
  return undefined;
}

function labelsOf(source: string, node: TSESTree.Node): Set<string> {
  if (node.type === 'Literal' || node.type === 'TemplateLiteral' || node.type === 'Identifier') {return new Set();}
  if (node.type === 'MemberExpression') {return isRequest(node) ? sourceLabels() : new Set();}
  if (node.type === 'BinaryExpression') {return union(labelsOf(source, node.left), labelsOf(source, node.right));}
  if (node.type === 'CallExpression') {return labelsOfCall(source, node);}
  return new Set();
}

function labelsOfCall(source: string, node: TSESTree.CallExpression): Set<string> {
  const arg = node.arguments[0];
  const inner = arg === undefined || arg.type === 'SpreadElement' ? new Set<string>() : labelsOf(source, arg);
  if (node.callee.type === 'Identifier') {
    const named = identifierSanitizer(node.callee.name) ?? sanitizerName(source, node);
    if (named !== undefined) {return applySanitizer(inner, named);}
  }
  const named = sanitizerName(source, node);
  if (named !== undefined) {return applySanitizer(inner, named);}
  return inner;
}

function isRequest(node: TSESTree.MemberExpression): boolean {
  let current: TSESTree.Node = node;
  while (current.type === 'MemberExpression') {current = current.object;}
  return current.type === 'Identifier' && current.name === 'req';
}

function union(left: Set<string>, right: Set<string>): Set<string> {
  const next = new Set(left);
  for (const label of right) {next.add(label);}
  return next;
}

function isAstNode(value: unknown): value is TSESTree.Node {
  return value !== null && typeof value === 'object' && 'type' in value;
}

function walkAst(node: TSESTree.Node, visit: (node: TSESTree.Node) => void): void {
  for (const key of Object.keys(node)) {
    if (key === 'parent') {continue;}
    const value = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isAstNode(item)) {visit(item);}
      }
    } else if (isAstNode(value)) {
      visit(value);
    }
  }
}

function sqlArgTainted(source: string, arg: TSESTree.CallExpressionArgument): boolean {
  return arg.type !== 'SpreadElement' && labelsOf(source, arg).has('sqli');
}

function sqlQueryReports(source: string, node: TSESTree.Node): boolean {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return false;}
  const property = node.callee.property;
  if (property.type !== 'Identifier' || property.name !== 'query') {return false;}
  return node.arguments.some((arg) => sqlArgTainted(source, arg));
}

function visitSql(source: string, node: TSESTree.Node, state: { report: boolean }): void {
  if (sqlQueryReports(source, node)) {state.report = true;}
  walkAst(node, (child) => { visitSql(source, child, state); });
}

/** SQL concatenation finding under the label algebra. Flag off reports nothing. */
export function sqlConcatReports(source: string): boolean {
  if (!labelsEnabled()) {return false;}
  const program = parse(source, {
    loc: true,
    range: true,
    jsx: false,
    comment: false,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  });
  const state = { report: false };
  visitSql(source, program, state);
  return state.report;
}
