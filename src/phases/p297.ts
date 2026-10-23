import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_TRPC';

export interface TrpcRoute {
  path: string;
  authState: 'present' | 'absent';
  injection: boolean;
  line: number;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeTrpc(source: string, options?: { file?: string }): { routes: TrpcRoute[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { routes: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { routes: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const events: UnsoundEvent[] = [];
  const routes: TrpcRoute[] = [];
  const walk = (node: TSESTree.Node, prefix: string): void => {
    if (node.type !== 'ObjectExpression') {return;}
    for (const prop of node.properties) {
      if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {continue;}
      const path = prefix.length === 0 ? prop.key.name : `${prefix}.${prop.key.name}`;
      if (prop.value.type === 'CallExpression') {noteProcedure(prop.value, path, routes, events, file);}
      if (prop.value.type === 'ObjectExpression') {walk(prop.value, path);}
    }
  };
  for (const stmt of program.body) {scanTrpc(stmt, routes, events, file, walk);}
  return { routes, events };
}

function scanTrpc(
  stmt: TSESTree.Statement,
  routes: TrpcRoute[],
  events: UnsoundEvent[],
  file: string,
  walk: (node: TSESTree.Node, prefix: string) => void,
): void {
  if (stmt.type !== 'VariableDeclaration') {return;}
  for (const decl of stmt.declarations) {scanTrpcDecl(decl, routes, events, file, walk);}
}

function scanTrpcDecl(
  decl: TSESTree.VariableDeclarator,
  routes: TrpcRoute[],
  events: UnsoundEvent[],
  file: string,
  walk: (node: TSESTree.Node, prefix: string) => void,
): void {
  if (decl.init === null || decl.init.type !== 'CallExpression') {return;}
  if (isRouter(decl.init)) {noteRouter(decl, walk); return;}
  const path = decl.id.type === 'Identifier' ? decl.id.name : 'proc';
  noteProcedure(decl.init, path, routes, events, file);
}

function isRouter(call: TSESTree.CallExpression): boolean {
  const callee = stripNode(call.callee);
  return callee.type === 'Identifier' && callee.name === 'router';
}

function noteRouter(decl: TSESTree.VariableDeclarator, walk: (node: TSESTree.Node, prefix: string) => void): void {
  if (decl.init === null || decl.init.type !== 'CallExpression') {return;}
  const arg = decl.init.arguments[0];
  const name = decl.id.type === 'Identifier' ? decl.id.name : '';
  if (arg !== undefined && arg.type === 'ObjectExpression') {walk(arg, name === 'appRouter' ? '' : name);}
}

function noteProcedure(call: TSESTree.CallExpression, path: string, routes: TrpcRoute[], events: UnsoundEvent[], file: string): void {
  const chain = chainOf(call);
  const kind = chain.find((part) => part === 'query' || part === 'mutation' || part === 'subscription');
  if (kind === undefined) {return;}
  const auth = chain.includes('use') || chain.includes('protectedProcedure');
  const zod = zodOf(call);
  if (zod.unknown) {events.push({ kind: 'unknown-callee', file, line: lineOf(call), reason: zod.unknown });}
  const handler = handlerOf(call);
  const injection = handler !== null && queriesInput(handler) && !zod.clears;
  routes.push({ path, authState: auth ? 'present' : 'absent', injection, line: lineOf(call) });
}

function chainOf(call: TSESTree.CallExpression): string[] {
  const names: string[] = [];
  let current: TSESTree.Node = call;
  while (current.type === 'CallExpression') {
    const callee = stripNode(current.callee);
    if (callee.type === 'MemberExpression') {
      const name = propName(callee);
      if (name !== null) {names.push(name);}
      if (callee.object.type === 'Identifier') {names.push(callee.object.name);}
      current = callee.object;
      continue;
    }
    if (callee.type === 'Identifier') {names.push(callee.name);}
    break;
  }
  return names;
}

function zodOf(call: TSESTree.CallExpression): { clears: boolean; unknown: string | null } {
  let current: TSESTree.Node = call;
  while (current.type === 'CallExpression') {
    const callee = stripNode(current.callee);
    if (callee.type === 'MemberExpression' && propName(callee) === 'input') {
      const arg = current.arguments[0];
      if (arg !== undefined && arg.type === 'CallExpression') {return classifyZod(arg);}
    }
    if (callee.type !== 'MemberExpression') {break;}
    current = callee.object;
  }
  return { clears: false, unknown: null };
}

function classifyZod(call: TSESTree.CallExpression): { clears: boolean; unknown: string | null } {
  const names: string[] = [];
  let current: TSESTree.Node = call;
  while (current.type === 'CallExpression') {
    const callee = stripNode(current.callee);
    if (callee.type === 'MemberExpression') {
      const name = propName(callee);
      if (name !== null) {names.push(name);}
      current = callee.object;
      continue;
    }
    break;
  }
  if (names.includes('number') || names.includes('enum')) {return { clears: true, unknown: null };}
  if (names.includes('regex')) {
    const pattern = regexPattern(call);
    if (pattern !== null && pattern.startsWith('^') && pattern.endsWith('$')) {return { clears: true, unknown: null };}
  }
  const known = new Set(['string', 'number', 'enum', 'object', 'regex', 'any']);
  const unknown = names.find((name) => !known.has(name) && name !== 'input');
  if (unknown !== undefined || names.includes('any')) {return { clears: false, unknown: unknown ?? null };}
  return { clears: false, unknown: null };
}

function regexPattern(call: TSESTree.CallExpression): string | null {
  let current: TSESTree.Node | null = call;
  while (current !== null && current.type === 'CallExpression') {
    const callee = stripNode(current.callee);
    if (callee.type === 'MemberExpression' && propName(callee) === 'regex') {
      const arg = current.arguments[0];
      if (arg !== undefined && arg.type === 'Literal' && 'regex' in arg && arg.regex !== null) {return arg.regex.pattern;}
      if (arg !== undefined && arg.type === 'Literal' && typeof arg.value === 'string') {return arg.value;}
    }
    current = callee.type === 'MemberExpression' ? callee.object : null;
  }
  return null;
}

function handlerOf(call: TSESTree.CallExpression): TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression | null {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return null;}
  const name = propName(callee);
  if (name !== 'query' && name !== 'mutation' && name !== 'subscription') {return null;}
  const arg = call.arguments[0];
  if (arg !== undefined && (arg.type === 'ArrowFunctionExpression' || arg.type === 'FunctionExpression')) {return arg;}
  return null;
}

function queriesInput(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression): boolean {
  const param = fn.params[0];
  const inputName = param !== undefined && param.type === 'ObjectPattern'
    ? param.properties.flatMap((item) => item.type === 'Property' && item.value.type === 'Identifier' ? [item.value.name] : [])
    : [];
  const body = fn.body.type === 'BlockStatement' ? fn.body.body : [];
  return body.some((stmt) => stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression' && uses(stmt.expression, inputName));
}

function uses(node: TSESTree.Node, names: readonly string[]): boolean {
  if (node.type === 'Identifier') {return names.includes(node.name);}
  if (node.type === 'CallExpression') {return node.arguments.some((arg) => arg.type !== 'SpreadElement' && uses(arg, names)) || uses(node.callee, names);}
  if (node.type === 'BinaryExpression') {return uses(node.left, names) || uses(node.right, names);}
  if (node.type === 'MemberExpression') {return uses(node.object, names);}
  return false;
}
