import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, walkAst, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_EXPRESS5';

export interface ExpressRoute {
  method: string;
  pattern: string;
  fullPath: string | null;
  splat: boolean;
  rejectionEdge: boolean;
  queryKeys: 'flat' | 'nested' | 'unknown';
}

export interface ExpressModel {
  routes: ExpressRoute[];
  events: UnsoundEvent[];
  findings: [];
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeExpress(source: string, options: { version: string; file?: string }): ExpressModel {
  if (!enabled()) {return { routes: [], events: [], findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { routes: [], events: [], findings: [] };}
  const file = options.file ?? 'inline.js';
  const major = majorOf(options.version);
  const parser = queryParser(program);
  const events: UnsoundEvent[] = [];
  let queryKeys: ExpressRoute['queryKeys'] = parser === null ? (major >= 5 ? 'flat' : 'nested') : parser === 'simple' ? 'flat' : parser === 'extended' ? 'nested' : 'unknown';
  if (parser !== null && parser !== 'simple' && parser !== 'extended') {
    events.push({ kind: 'unknown-callee', file, line: 1, reason: 'query parser' });
    queryKeys = 'unknown';
  }
  const asyncFns = asyncFunctions(program);
  const hasError = hasArity4(program);
  const routes: ExpressRoute[] = [];
  const ctx: ExpressCtx = { major, asyncFns, hasError, queryKeys, file, events };
  for (const stmt of program.body) {
    const route = expressRoute(stmt, ctx);
    if (route !== null) {routes.push(route);}
  }
  return { routes, events, findings: [] };
}

interface ExpressCtx {
  major: number;
  asyncFns: ReadonlySet<string>;
  hasError: boolean;
  queryKeys: ExpressRoute['queryKeys'];
  file: string;
  events: UnsoundEvent[];
}

function expressRoute(stmt: TSESTree.Statement, ctx: ExpressCtx): ExpressRoute | null {
  const found = routeCall(stmt);
  if (found === null) {return null;}
  const patternNode = found.call.arguments[0];
  if (patternNode === undefined || patternNode.type !== 'Literal' || typeof patternNode.value !== 'string') {return null;}
  const handler = found.call.arguments[1];
  const asyncHandler = handler !== undefined && isAsyncHandler(handler, ctx.asyncFns);
  const compiled = compilePattern(patternNode.value, ctx.major, ctx.file, lineOf(found.call), ctx.events);
  return {
    method: found.method,
    pattern: patternNode.value,
    fullPath: compiled.fullPath,
    splat: compiled.splat,
    rejectionEdge: ctx.major >= 5 && asyncHandler && ctx.hasError,
    queryKeys: ctx.queryKeys,
  };
}

function routeCall(stmt: TSESTree.Statement): { method: string; call: TSESTree.CallExpression } | null {
  if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {return null;}
  const callee = stripNode(stmt.expression.callee);
  if (callee.type !== 'MemberExpression') {return null;}
  const method = propName(callee);
  if (!isRouteMethod(method)) {return null;}
  return { method, call: stmt.expression };
}

function isRouteMethod(method: string | null): method is string {
  return method === 'get' || method === 'post' || method === 'put' || method === 'patch' || method === 'delete';
}

function majorOf(version: string): number {
  const match = /(\d+)/.exec(version);
  return match === null ? 4 : Number(match[1]);
}

function queryParser(program: TSESTree.Program): string | null {
  for (const stmt of program.body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    const call = stmt.expression;
    const callee = stripNode(call.callee);
    if (callee.type !== 'MemberExpression' || propName(callee) !== 'set') {continue;}
    const key = call.arguments[0];
    const value = call.arguments[1];
    if (key !== undefined && key.type === 'Literal' && key.value === 'query parser' && value !== undefined && value.type === 'Literal' && typeof value.value === 'string') {
      return value.value;
    }
  }
  return null;
}

function asyncFunctions(program: TSESTree.Program): Set<string> {
  const names = new Set<string>();
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.async && stmt.id !== null) {names.add(stmt.id.name);}
  }
  walkAst(program, (node) => {
    if ((node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') && node.async && node.id !== null) {names.add(node.id.name);}
  });
  return names;
}

function hasArity4(program: TSESTree.Program): boolean {
  let found = false;
  walkAst(program, (node) => {
    if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
      if (node.params.length === 4) {found = true;}
    }
  });
  return found;
}

function isAsyncHandler(node: TSESTree.Node, asyncFns: ReadonlySet<string>): boolean {
  if ((node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression') && node.async) {return true;}
  return node.type === 'Identifier' && asyncFns.has(node.name);
}

function compilePattern(pattern: string, major: number, file: string, line: number, events: UnsoundEvent[]): { fullPath: string | null; splat: boolean } {
  if (major < 5) {return { fullPath: pattern, splat: false };}
  if (pattern.includes('(')) {
    events.push({ kind: 'unresolved-import', file, line, reason: 'inline regex' });
    return { fullPath: null, splat: false };
  }
  const fullPath = pattern.replaceAll('{', '').replaceAll('}', '');
  return { fullPath, splat: pattern.includes('/*') };
}
