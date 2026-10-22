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

function sanitizerName(source: string, node: TSESTree.CallExpression): string | undefined {
  const callee = node.callee;
  if (callee.type === 'Identifier') {
    if (callee.name === 'Number' || callee.name === 'isInt' || callee.name === 'escapeHtml' || callee.name === 'shellQuote' || callee.name === 'mongoSanitize' || callee.name === 'allowlist') {
      return callee.name;
    }
    if (callee.name === 'parse') {return 'parse';}
    return undefined;
  }
  if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier') {return undefined;}
  const property = callee.property.name;
  const objectText = slice(source, callee.object);
  if (property === 'sanitize' && objectText.includes('DOMPurify')) {return 'DOMPurify';}
  if (property === 'escape' && objectText.includes('validator')) {return 'validator.escape';}
  if (property === 'escape') {return 'he.escape';}
  if (property === 'parse' && /z\.number|zod\.number/.test(objectText)) {return 'z.number';}
  if (property === 'parse' && objectText === 'JSON') {return 'JSON.parse';}
  if (property === 'parse' && /\.string\(/.test(objectText)) {return 'z.string';}
  if (callee.object.type === 'Identifier' && callee.object.name === 'encodeURIComponent') {return undefined;}
  if (property === 'encodeURIComponent') {return 'encodeURIComponent';}
  return undefined;
}

function identifierSanitizer(name: string): string | undefined {
  if (name === 'encodeURIComponent' || name === 'encodeURI' || name === 'decodeURIComponent') {return name;}
  return undefined;
}

function labelsOf(source: string, node: TSESTree.Node): Set<string> {
  switch (node.type) {
    case 'Literal':
    case 'TemplateLiteral':
      return new Set();
    case 'Identifier':
      return new Set();
    case 'MemberExpression':
      return isRequest(node) ? sourceLabels() : new Set();
    case 'BinaryExpression':
      return union(labelsOf(source, node.left), labelsOf(source, node.right));
    case 'CallExpression':
      return labelsOfCall(source, node);
    default:
      return new Set();
  }
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
  let report = false;
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const property = node.callee.property;
      if (property.type === 'Identifier' && property.name === 'query') {
        for (const arg of node.arguments) {
          if (arg.type === 'SpreadElement') {continue;}
          if (labelsOf(source, arg).has('sqli')) {report = true;}
        }
      }
    }
    for (const key of Object.keys(node)) {
      if (key === 'parent') {continue;}
      const value = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item !== null && typeof item === 'object' && 'type' in item) {visit(item as TSESTree.Node);}
        }
      } else if (value !== null && typeof value === 'object' && 'type' in value) {
        visit(value as TSESTree.Node);
      }
    }
  };
  visit(program);
  return report;
}
