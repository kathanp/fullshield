import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_STOREDLINK';

export interface LinkFinding {
  file: string;
  line: number;
  origin: 'stored';
  confidence: 'medium' | 'high';
  routes: string[];
}

interface Write {
  model: string;
  field: string;
  route: string;
  untrusted: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeStoredLink(source: string, options?: { file?: string }): { findings: LinkFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const writes: Write[] = [];
  const findings: LinkFinding[] = [];
  for (const stmt of program.body) {collectRouteWrites(stmt, writes);}
  for (const stmt of program.body) {scanRoute(stmt, writes, findings, file);}
  return { findings };
}

function routeCall(stmt: TSESTree.Statement): { route: string; handler: TSESTree.Statement[] } | null {
  if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {return null;}
  const route = routeOf(stmt.expression);
  const handler = handlerBody(stmt.expression);
  if (route === null || handler === null) {return null;}
  return { route, handler };
}

function collectRouteWrites(stmt: TSESTree.Statement, writes: Write[]): void {
  const route = routeCall(stmt);
  if (route === null) {return;}
  for (const inner of route.handler) {collectWrite(inner, route.route, writes);}
}

function scanRoute(stmt: TSESTree.Statement, writes: readonly Write[], findings: LinkFinding[], file: string): void {
  const route = routeCall(stmt);
  if (route === null) {return;}
  scanReads(route.handler, route.route, writes, findings, file);
}

function scanReads(
  body: readonly TSESTree.Statement[],
  route: string,
  writes: readonly Write[],
  findings: LinkFinding[],
  file: string,
): void {
  const reads = new Map<string, string>();
  const out: LinkOut = { route, writes, findings, file };
  for (const stmt of body) {
    if (stmt.type === 'VariableDeclaration') {collectReads(stmt, reads);}
    noteReadSink(stmt, reads, out);
  }
}

interface LinkOut {
  route: string;
  writes: readonly Write[];
  findings: LinkFinding[];
  file: string;
}

function collectReads(stmt: TSESTree.VariableDeclaration, reads: Map<string, string>): void {
  for (const decl of stmt.declarations) {noteFind(decl, reads);}
}

function noteFind(decl: TSESTree.VariableDeclarator, reads: Map<string, string>): void {
  if (decl.id.type !== 'Identifier' || decl.init === null || decl.init.type !== 'CallExpression') {return;}
  const callee = stripNode(decl.init.callee);
  if (callee.type !== 'MemberExpression' || callee.object.type !== 'Identifier') {return;}
  const method = propName(callee) ?? '';
  if (method.startsWith('find')) {reads.set(decl.id.name, callee.object.name);}
}

function noteReadSink(stmt: TSESTree.Statement, reads: ReadonlyMap<string, string>, out: LinkOut): void {
  const read = readField(stmt, reads);
  if (read === null) {return;}
  pushLink(read, out);
}

function readField(stmt: TSESTree.Statement, reads: ReadonlyMap<string, string>): { call: TSESTree.CallExpression; model: string; field: string } | null {
  if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {return null;}
  const call = stmt.expression;
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || (propName(callee) !== 'send' && propName(callee) !== 'write')) {return null;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type !== 'MemberExpression' || arg.object.type !== 'Identifier') {return null;}
  if (arg.property.type !== 'Identifier') {return null;}
  const model = reads.get(arg.object.name);
  if (model === undefined) {return null;}
  return { call, model, field: arg.property.name };
}

function pushLink(read: { call: TSESTree.CallExpression; model: string; field: string }, out: LinkOut): void {
  const linked = out.writes.find((write) => write.model === read.model && write.field === read.field && write.untrusted);
  const known = out.writes.some((write) => write.model === read.model && write.field === read.field);
  if (!known && out.writes.every((write) => write.model !== read.model)) {
    out.findings.push({ file: out.file, line: lineOf(read.call), origin: 'stored', confidence: 'medium', routes: [out.route] });
    return;
  }
  out.findings.push({
    file: out.file,
    line: lineOf(read.call),
    origin: 'stored',
    confidence: linked === undefined ? 'medium' : 'high',
    routes: linked === undefined ? [out.route] : [linked.route, out.route],
  });
}

function collectWrite(stmt: TSESTree.Statement, route: string, writes: Write[]): void {
  if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {noteWrite(stmt.expression, route, writes);}
  if (stmt.type === 'BlockStatement') {
    for (const inner of stmt.body) {collectWrite(inner, route, writes);}
  }
}

function noteWrite(call: TSESTree.CallExpression, route: string, writes: Write[]): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || callee.object.type !== 'Identifier') {return;}
  const method = propName(callee);
  if (!isWriteMethod(method)) {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type !== 'ObjectExpression') {return;}
  pushWriteFields(arg, callee.object.name, route, writes);
}

function isWriteMethod(method: string | null): boolean {
  return method === 'create' || method === 'update' || method === 'save' || method === 'insert';
}

function pushWriteFields(arg: TSESTree.ObjectExpression, model: string, route: string, writes: Write[]): void {
  for (const prop of arg.properties) {
    if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {continue;}
    writes.push({ model, field: prop.key.name, route, untrusted: exprUntrusted(prop.value) });
  }
}

function routeOf(call: TSESTree.CallExpression): string | null {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return null;}
  const method = propName(callee);
  if (method !== 'get' && method !== 'post' && method !== 'put' && method !== 'patch' && method !== 'delete') {return null;}
  const arg = call.arguments[0];
  if (arg !== undefined && arg.type === 'Literal' && typeof arg.value === 'string') {return arg.value;}
  return null;
}

function handlerBody(call: TSESTree.CallExpression): TSESTree.Statement[] | null {
  const handler = call.arguments[1];
  if (handler === undefined || (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression')) {return null;}
  if (handler.body.type === 'BlockStatement') {return handler.body.body;}
  return [];
}

function exprUntrusted(node: TSESTree.Node): boolean {
  if (isRequestSource(node)) {return true;}
  if (node.type === 'MemberExpression') {return exprUntrusted(node.object);}
  return false;
}
