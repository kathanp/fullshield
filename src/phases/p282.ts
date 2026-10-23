import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode, walkAst } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_HTMLCTX';

const HTML_CONTEXTS = [
  'text',
  'quoted-attr',
  'unquoted-attr',
  'url-attr',
  'event-handler',
  'script',
  'style',
  'comment',
] as const;

const HTML_SANITIZERS = [
  'none',
  'escapeHtml',
  'encodeURIComponent',
  'jsonStringify',
  'dompurify',
  'textContent',
] as const;

export type HtmlContext = (typeof HTML_CONTEXTS)[number];
export type HtmlSanitizer = (typeof HTML_SANITIZERS)[number];

export interface HtmlFinding {
  file: string;
  line: number;
  htmlContext: HtmlContext;
}

const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction']);

interface Scan {
  mode: 'text' | 'tag' | 'attr-name' | 'attr-value' | 'script' | 'style' | 'comment';
  attr: string;
  quote: '"' | "'" | '';
  tag: string;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function sanitizerClears(context: HtmlContext, sanitizer: HtmlSanitizer): boolean {
  if (sanitizer === 'none' || sanitizer === 'jsonStringify' || sanitizer === 'encodeURIComponent') {return false;}
  if (sanitizer === 'escapeHtml') {return context === 'text' || context === 'quoted-attr';}
  if (sanitizer === 'textContent') {return context === 'text';}
  return context === 'text' || context === 'quoted-attr' || context === 'unquoted-attr' || context === 'comment' || context === 'style';
}

export function htmlContextOf(prefix: string): HtmlContext {
  return contextOf(scan(prefix));
}

export function analyzeHtml(source: string, options?: { file?: string }): { findings: HtmlFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const findings: HtmlFinding[] = [];
  walkAst(program, (node) => {
    if (node.type !== 'TemplateLiteral') {return;}
    if (!isHtmlSink(node)) {return;}
    node.expressions.forEach((expr, index) => {
      const quasi = node.quasis[index];
      if (quasi === undefined || !exprTainted(expr)) {return;}
      const context = htmlContextOf(quasi.value.cooked ?? '');
      const sanitizer = sanitizerOf(expr);
      if (sanitizerClears(context, sanitizer)) {return;}
      findings.push({ file, line: lineOf(expr), htmlContext: context });
    });
  });
  return { findings };
}

function isHtmlSink(node: TSESTree.TemplateLiteral): boolean {
  const parent = findSink(node);
  return parent;
}

function findSink(node: TSESTree.TemplateLiteral): boolean {
  const cooked = node.quasis.map((quasi) => quasi.value.cooked ?? '').join('');
  return cooked.includes('<') || cooked.includes('</');
}

function exprTainted(node: TSESTree.Node): boolean {
  let hit = false;
  walkAst(node, (current) => {
    if (isRequestSource(current) || current.type === 'Identifier') {hit = true;}
  });
  return hit;
}

function sanitizerOf(node: TSESTree.Node): HtmlSanitizer {
  const current = stripNode(node);
  if (current.type !== 'CallExpression') {return 'none';}
  const callee = stripNode(current.callee);
  if (callee.type === 'Identifier') {
    if (callee.name === 'escapeHtml' || callee.name === 'encodeHTML') {return 'escapeHtml';}
    if (callee.name === 'encodeURIComponent') {return 'encodeURIComponent';}
    if (callee.name === 'JSON' ) {return 'none';}
  }
  if (callee.type === 'MemberExpression') {
    const name = propName(callee);
    if (name === 'stringify' && callee.object.type === 'Identifier' && callee.object.name === 'JSON') {return 'jsonStringify';}
    if (name === 'sanitize') {return 'dompurify';}
  }
  return 'none';
}

function scan(prefix: string): Scan {
  const state: Scan = { mode: 'text', attr: '', quote: '', tag: '' };
  for (let i = 0; i < prefix.length; i += 1) {
    i += scanAt(state, prefix, i);
  }
  return state;
}

function scanAt(state: Scan, prefix: string, i: number): number {
  const ch = prefix[i] ?? '';
  const next = prefix[i + 1] ?? '';
  if (state.mode === 'comment') {return closeComment(state, prefix, i, ch, next);}
  if (state.mode === 'script') {return closeRegion(state, prefix, i, '</script>', 8);}
  if (state.mode === 'style') {return closeRegion(state, prefix, i, '</style>', 7);}
  if (state.mode === 'text') {return scanText(state, ch, next);}
  if (state.mode === 'tag') {return scanTag(state, ch);}
  if (state.mode === 'attr-name') {return scanAttrName(state, ch);}
  return scanAttrValue(state, ch);
}

function closeComment(state: Scan, prefix: string, i: number, ch: string, next: string): number {
  if (ch === '-' && next === '-' && (prefix[i + 2] ?? '') === '>') {
    state.mode = 'text';
    return 2;
  }
  return 0;
}

function closeRegion(state: Scan, prefix: string, i: number, token: string, extra: number): number {
  if (prefix.slice(i, i + token.length).toLowerCase() === token) {
    state.mode = 'text';
    return extra;
  }
  return 0;
}

function scanText(state: Scan, ch: string, next: string): number {
  if (ch === '<' && next === '!') {state.mode = 'comment'; return 0;}
  if (ch === '<') {state.mode = 'tag'; state.tag = ''; state.attr = '';}
  return 0;
}

function scanTag(state: Scan, ch: string): number {
  if (ch === '>') {enterTag(state); return 0;}
  if (ch === ' ' || ch === '\n') {state.mode = 'attr-name'; state.attr = ''; return 0;}
  if (ch !== '/') {state.tag += ch;}
  return 0;
}

function scanAttrName(state: Scan, ch: string): number {
  if (ch === '>') {enterTag(state); return 0;}
  if (ch === '=') {state.mode = 'attr-value'; state.quote = ''; return 0;}
  if (ch !== ' ') {state.attr += ch;}
  return 0;
}

function scanAttrValue(state: Scan, ch: string): number {
  if (ch === '>' && state.quote === '') {enterTag(state); return 0;}
  if (state.quote === '' && (ch === '"' || ch === "'")) {state.quote = ch; return 0;}
  if (state.quote !== '' && ch === state.quote) {state.mode = 'attr-name'; state.attr = ''; state.quote = '';}
  return 0;
}

function enterTag(state: Scan): void {
  const tag = state.tag.toLowerCase();
  if (tag === 'script') {state.mode = 'script';}
  else if (tag === 'style') {state.mode = 'style';}
  else {state.mode = 'text';}
  state.tag = '';
  state.attr = '';
}

function contextOf(state: Scan): HtmlContext {
  if (state.mode === 'comment') {return 'comment';}
  if (state.mode === 'script') {return 'script';}
  if (state.mode === 'style') {return 'style';}
  if (state.mode === 'attr-value' || (state.mode === 'attr-name' && state.quote !== '')) {
    const attr = state.attr.toLowerCase();
    if (attr.startsWith('on')) {return 'event-handler';}
    if (URL_ATTRS.has(attr)) {return 'url-attr';}
    if (state.quote === '') {return 'unquoted-attr';}
    return 'quoted-attr';
  }
  return 'text';
}
