import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode } from './p271.js';
import { abstractExpression, labelsOf, type AbstractString, type CharClass } from './p278.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_URLCTX';

export type SsrfContext = 'authority' | 'path' | 'query' | 'fragment';

export interface UrlFinding {
  file: string;
  line: number;
  ssrfContext: SsrfContext;
  severity: 'high' | 'medium' | 'low';
  origin: 'request';
}

const SINKS = new Set(['fetch', 'get', 'request']);

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeUrl(source: string, options?: { file?: string }): { findings: UrlFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const findings: UrlFinding[] = [];
  const env = new Map<string, AbstractString>();
  const walk = (stmts: readonly TSESTree.Statement[]): void => {
    for (const stmt of stmts) {
      if (stmt.type === 'FunctionDeclaration') {walk(stmt.body.body); continue;}
      if (stmt.type === 'BlockStatement') {walk(stmt.body); continue;}
      if (stmt.type === 'IfStatement') {
        walk(stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent]);
        if (stmt.alternate !== null) {walk(stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate]);}
        continue;
      }
      if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations) {
          if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, abstractExpression(decl.init, env));}
        }
        continue;
      }
      if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {note(stmt.expression, env, file, findings);}
      if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'NewExpression') {noteNew(stmt.expression, env, file, findings);}
    }
  };
  walk(program.body);
  return { findings };
}

function note(call: TSESTree.CallExpression, env: ReadonlyMap<string, AbstractString>, file: string, findings: UrlFinding[]): void {
  const callee = stripNode(call.callee);
  const name = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' ? propName(callee) : null;
  if (name === null || !SINKS.has(name)) {return;}
  if (callee.type === 'NewExpression') {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  const value = abstractExpression(arg, env);
  if (labelsOf(value).length === 0 && !containsRequest(arg)) {return;}
  const context = contextAt(prefixBeforeHole(value));
  findings.push({ file, line: lineOf(call), ssrfContext: context, severity: severityOf(context), origin: 'request' });
}

function noteNew(node: TSESTree.NewExpression, env: ReadonlyMap<string, AbstractString>, file: string, findings: UrlFinding[]): void {
  if (node.callee.type !== 'Identifier' || node.callee.name !== 'URL') {return;}
  const arg = node.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  const value = abstractExpression(arg, env);
  if (labelsOf(value).length === 0) {return;}
  const charClass = charClassOf(value);
  const context = charClass === 'digits' || charClass === 'numeric' || charClass === 'letters' ? contextAt(literalBase(node) + prefixBeforeHole(value)) : 'authority';
  findings.push({ file, line: lineOf(node), ssrfContext: context, severity: severityOf(context), origin: 'request' });
}

function prefixBeforeHole(value: AbstractString): string {
  let prefix = '';
  for (const seg of value.segments) {
    if (seg.kind !== 'literal') {return prefix;}
    prefix += seg.text;
  }
  return prefix;
}

function contextAt(prefix: string): SsrfContext {
  const scheme = prefix.indexOf('://');
  if (scheme < 0) {return 'authority';}
  const after = prefix.slice(scheme + 3);
  const slash = after.indexOf('/');
  if (slash < 0) {return 'authority';}
  const hash = prefix.lastIndexOf('#');
  const query = prefix.lastIndexOf('?');
  if (hash >= 0 && hash > slash + scheme) {return 'fragment';}
  if (query >= 0 && query > slash + scheme) {return 'query';}
  return 'path';
}

function severityOf(context: SsrfContext): 'high' | 'medium' | 'low' {
  if (context === 'authority') {return 'high';}
  if (context === 'path') {return 'medium';}
  return 'low';
}

function charClassOf(value: AbstractString): CharClass | 'any' {
  const hole = value.segments.find((seg) => seg.kind === 'tainted');
  return hole !== undefined && hole.kind === 'tainted' ? hole.charClass : 'any';
}

function literalBase(node: TSESTree.NewExpression): string {
  const base = node.arguments[1];
  if (base !== undefined && base.type === 'Literal' && typeof base.value === 'string') {return base.value;}
  return '';
}

function containsRequest(node: TSESTree.Node): boolean {
  if (isRequestSource(node)) {return true;}
  if (node.type === 'BinaryExpression') {return containsRequest(node.left) || containsRequest(node.right);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => containsRequest(expr));}
  return false;
}
