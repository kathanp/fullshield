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
  if (current.type === 'MemberExpression' && current.object.type === 'Identifier' && current.property.type === 'Identifier' && !current.computed) {
    const field = env.get(current.object.name)?.fields.get(current.property.name);
    return field ?? NONE;
  }
  if (current.type === 'ObjectExpression') {
    const fields = new Map<string, Val>();
    const labels = new Set<string>();
    for (const prop of current.properties) {
      if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {continue;}
      const value = evalExpr(prop.value, env);
      fields.set(prop.key.name, value);
      for (const label of value.labels) {labels.add(label);}
    }
    return { labels: [...labels], fields, saved: null };
  }
  if (current.type === 'CallExpression') {return evalCall(current, env);}
  if (current.type === 'BinaryExpression') {
    const left = evalExpr(current.left, env);
    const right = evalExpr(current.right, env);
    return { labels: [...new Set([...left.labels, ...right.labels])], fields: new Map(), saved: null };
  }
  return NONE;
}

function evalCall(call: TSESTree.CallExpression, env: ReadonlyMap<string, Val>): Val {
  const callee = stripNode(call.callee);
  const name = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' ? propName(callee) : null;
  const object = callee.type === 'MemberExpression' && callee.object.type === 'Identifier' ? callee.object.name : null;
  const arg0 = call.arguments[0];
  const inner = arg0 === undefined || arg0.type === 'SpreadElement' ? NONE : evalExpr(arg0, env);
  if (name === 'stringify' && object === 'JSON') {return { labels: inner.labels, fields: inner.fields, saved: inner };}
  if (name === 'parse' && object === 'JSON') {return inner.saved ?? inner;}
  if (name === 'structuredClone') {return { labels: inner.labels, fields: new Map(inner.fields), saved: inner.saved };}
  if (name === 'stringify' && (object === 'querystring' || object === 'qs')) {return { labels: inner.labels, fields: inner.fields, saved: inner };}
  if (name === 'parse' && (object === 'querystring' || object === 'qs')) {return inner.saved ?? inner;}
  if (name === 'from' && object === 'Buffer') {return { labels: inner.labels, fields: new Map(), saved: inner };}
  if (name === 'toString' && callee.type === 'MemberExpression') {
    const receiver = evalExpr(callee.object, env);
    return receiver.saved ?? receiver;
  }
  if (name === 'btoa' || name === 'encodeURIComponent') {return { labels: [], fields: new Map(), saved: inner };}
  if (name === 'atob' || name === 'decodeURIComponent') {return inner.saved ?? inner;}
  if ((name === 'gzipSync' || name === 'deflateSync') && inner.labels.length > 0) {return { labels: inner.labels, fields: new Map(), saved: inner };}
  if (name === 'gunzipSync' || name === 'inflateSync') {return inner.saved ?? inner;}
  return inner;
}
