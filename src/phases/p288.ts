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
  for (const stmt of program.body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    const route = routeOf(stmt.expression);
    if (route === null) {continue;}
    const handler = handlerBody(stmt.expression);
    if (handler === null) {continue;}
    for (const inner of handler) {collectWrite(inner, route, writes);}
  }
  for (const stmt of program.body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    const route = routeOf(stmt.expression);
    const handler = handlerBody(stmt.expression);
    if (route === null || handler === null) {continue;}
    scanReads(handler, route, writes, findings, file);
  }
  return { findings };
}

function scanReads(
  body: readonly TSESTree.Statement[],
  route: string,
  writes: readonly Write[],
  findings: LinkFinding[],
  file: string,
): void {
  const reads = new Map<string, string>();
  for (const stmt of body) {
    if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) {
        if (decl.id.type !== 'Identifier' || decl.init === null || decl.init.type !== 'CallExpression') {continue;}
        const callee = stripNode(decl.init.callee);
        if (callee.type !== 'MemberExpression' || callee.object.type !== 'Identifier') {continue;}
        const method = propName(callee) ?? '';
        if (method.startsWith('find')) {reads.set(decl.id.name, callee.object.name);}
      }
    }
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    const call = stmt.expression;
    const callee = stripNode(call.callee);
    if (callee.type !== 'MemberExpression' || (propName(callee) !== 'send' && propName(callee) !== 'write')) {continue;}
    const arg = call.arguments[0];
    if (arg === undefined || arg.type !== 'MemberExpression' || arg.object.type !== 'Identifier') {continue;}
    const property = arg.property;
    if (property.type !== 'Identifier') {continue;}
    const model = reads.get(arg.object.name);
    if (model === undefined) {continue;}
    const linked = writes.find((write) => write.model === model && write.field === property.name && write.untrusted);
    const known = writes.some((write) => write.model === model && write.field === property.name);
    if (!known && writes.every((write) => write.model !== model)) {
      findings.push({ file, line: lineOf(call), origin: 'stored', confidence: 'medium', routes: [route] });
      continue;
    }
    findings.push({
      file,
      line: lineOf(call),
      origin: 'stored',
      confidence: linked === undefined ? 'medium' : 'high',
      routes: linked === undefined ? [route] : [linked.route, route],
    });
  }
}

function collectWrite(stmt: TSESTree.Statement, route: string, writes: Write[]): void {
  if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
    const call = stmt.expression;
    const callee = stripNode(call.callee);
    if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier') {
      const method = propName(callee);
      if (method === 'create' || method === 'update' || method === 'save' || method === 'insert') {
        const arg = call.arguments[0];
        if (arg !== undefined && arg.type === 'ObjectExpression') {
          for (const prop of arg.properties) {
            if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {continue;}
            writes.push({
              model: callee.object.name,
              field: prop.key.name,
              route,
              untrusted: exprUntrusted(prop.value),
            });
          }
        }
      }
    }
  }
  if (stmt.type === 'BlockStatement') {
    for (const inner of stmt.body) {collectWrite(inner, route, writes);}
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
