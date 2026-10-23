import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ROUNDTRIP';

export interface RoundFinding {
  file: string;
  line: number;
  labels: string[];
  field?: string;
}

interface Val {
  labels: string[];
  fields: Map<string, Val>;
  saved: Val | null;
}

const NONE: Val = { labels: [], fields: new Map(), saved: null };

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeRoundTrip(source: string, options?: { file?: string }): { findings: RoundFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const findings: RoundFinding[] = [];
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration') {execBlock(stmt.body.body, new Map(), findings, file);}
  }
  return { findings };
}

function execBlock(stmts: readonly TSESTree.Statement[], env: Map<string, Val>, findings: RoundFinding[], file: string): void {
  for (const stmt of stmts) {exec(stmt, env, findings, file);}
}

function exec(stmt: TSESTree.Statement, env: Map<string, Val>, findings: RoundFinding[], file: string): void {
  if (stmt.type === 'BlockStatement') {execBlock(stmt.body, env, findings, file); return;}
  if (stmt.type === 'VariableDeclaration') {
    for (const decl of stmt.declarations) {
      if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, evalExpr(decl.init, env));}
    }
    return;
  }
  if (stmt.type === 'ExpressionStatement') {
    const expr = stripNode(stmt.expression);
    if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {env.set(expr.left.name, evalExpr(expr.right, env));}
    if (expr.type === 'CallExpression') {noteSink(expr, env, findings, file);}
  }
  if (stmt.type === 'IfStatement') {
    exec(stmt.consequent, env, findings, file);
    if (stmt.alternate !== null) {exec(stmt.alternate, env, findings, file);}
  }
}

function noteSink(call: TSESTree.CallExpression, env: ReadonlyMap<string, Val>, findings: RoundFinding[], file: string): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || (propName(callee) !== 'query' && propName(callee) !== 'send' && propName(callee) !== 'exec')) {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  const value = evalExpr(arg, env);
  if (value.labels.length === 0) {return;}
  const field = arg.type === 'MemberExpression' && !arg.computed && arg.property.type === 'Identifier' ? arg.property.name : undefined;
  findings.push({ file, line: lineOf(call), labels: value.labels, ...(field === undefined ? {} : { field }) });
}

function evalExpr(node: TSESTree.Node, env: ReadonlyMap<string, Val>): Val {
  const current = stripNode(node);
  if (isRequestSource(current)) {return { labels: ['sqli'], fields: new Map(), saved: null };}
  if (current.type === 'Identifier') {return env.get(current.name) ?? NONE;}
  if (isFieldRead(current)) {return readField(current, env);}
  if (current.type === 'ObjectExpression') {return evalObject(current, env);}
  if (current.type === 'CallExpression') {return evalCall(current, env);}
  if (current.type === 'BinaryExpression') {return evalBinary(current, env);}
  return NONE;
}

function isFieldRead(current: TSESTree.Node): current is TSESTree.MemberExpression & { object: TSESTree.Identifier; property: TSESTree.Identifier } {
  return current.type === 'MemberExpression'
    && current.object.type === 'Identifier'
    && current.property.type === 'Identifier'
    && !current.computed;
}

function readField(current: TSESTree.MemberExpression & { object: TSESTree.Identifier; property: TSESTree.Identifier }, env: ReadonlyMap<string, Val>): Val {
  return env.get(current.object.name)?.fields.get(current.property.name) ?? NONE;
}

function evalObject(current: TSESTree.ObjectExpression, env: ReadonlyMap<string, Val>): Val {
  const fields = new Map<string, Val>();
  const labels = new Set<string>();
  for (const prop of current.properties) {addField(prop, fields, labels, env);}
  return { labels: [...labels], fields, saved: null };
}

function addField(prop: TSESTree.ObjectLiteralElement, fields: Map<string, Val>, labels: Set<string>, env: ReadonlyMap<string, Val>): void {
  if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {return;}
  const value = evalExpr(prop.value, env);
  fields.set(prop.key.name, value);
  for (const label of value.labels) {labels.add(label);}
}

function evalBinary(current: TSESTree.BinaryExpression, env: ReadonlyMap<string, Val>): Val {
  const left = evalExpr(current.left, env);
  const right = evalExpr(current.right, env);
  return { labels: [...new Set([...left.labels, ...right.labels])], fields: new Map(), saved: null };
}

function evalCall(call: TSESTree.CallExpression, env: ReadonlyMap<string, Val>): Val {
  const callee = stripNode(call.callee);
  const name = callName(callee);
  const object = callObject(callee);
  const inner = callInner(call, env);
  return dispatchCall(name, object, callee, inner, env) ?? inner;
}

function callName(callee: TSESTree.Node): string | null {
  if (callee.type === 'Identifier') {return callee.name;}
  if (callee.type === 'MemberExpression') {return propName(callee);}
  return null;
}

function callObject(callee: TSESTree.Node): string | null {
  if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier') {return callee.object.name;}
  return null;
}

function callInner(call: TSESTree.CallExpression, env: ReadonlyMap<string, Val>): Val {
  const arg0 = call.arguments[0];
  if (arg0 === undefined || arg0.type === 'SpreadElement') {return NONE;}
  return evalExpr(arg0, env);
}

function dispatchCall(name: string | null, object: string | null, callee: TSESTree.Node, inner: Val, env: ReadonlyMap<string, Val>): Val | null {
  return jsonCall(name, object, inner)
    ?? cloneCall(name, inner)
    ?? qsCall(name, object, inner)
    ?? bufferCall(name, object, callee, inner, env)
    ?? codecCall(name, inner)
    ?? compressCall(name, inner);
}

function jsonCall(name: string | null, object: string | null, inner: Val): Val | null {
  if (name === 'stringify' && object === 'JSON') {return { labels: inner.labels, fields: inner.fields, saved: inner };}
  if (name === 'parse' && object === 'JSON') {return inner.saved ?? inner;}
  return null;
}

function cloneCall(name: string | null, inner: Val): Val | null {
  if (name !== 'structuredClone') {return null;}
  return { labels: inner.labels, fields: new Map(inner.fields), saved: inner.saved };
}

function qsCall(name: string | null, object: string | null, inner: Val): Val | null {
  if (!isQs(object)) {return null;}
  if (name === 'stringify') {return { labels: inner.labels, fields: inner.fields, saved: inner };}
  if (name === 'parse') {return inner.saved ?? inner;}
  return null;
}

function isQs(object: string | null): boolean {
  return object === 'querystring' || object === 'qs';
}

function bufferCall(name: string | null, object: string | null, callee: TSESTree.Node, inner: Val, env: ReadonlyMap<string, Val>): Val | null {
  if (name === 'from' && object === 'Buffer') {return { labels: inner.labels, fields: new Map(), saved: inner };}
  if (name === 'toString' && callee.type === 'MemberExpression') {return toStringValue(callee.object, env);}
  return null;
}

function toStringValue(object: TSESTree.Node, env: ReadonlyMap<string, Val>): Val {
  const receiver = evalExpr(object, env);
  return receiver.saved ?? receiver;
}

function codecCall(name: string | null, inner: Val): Val | null {
  if (name === 'btoa' || name === 'encodeURIComponent') {return { labels: [], fields: new Map(), saved: inner };}
  if (name === 'atob' || name === 'decodeURIComponent') {return inner.saved ?? inner;}
  return null;
}

function compressCall(name: string | null, inner: Val): Val | null {
  if ((name === 'gzipSync' || name === 'deflateSync') && inner.labels.length > 0) {
    return { labels: inner.labels, fields: new Map(), saved: inner };
  }
  if (name === 'gunzipSync' || name === 'inflateSync') {return inner.saved ?? inner;}
  return null;
}
