import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_XREQ';

export interface XreqFinding {
  file: string;
  line: number;
  origin: 'session' | 'cache';
  routes: string[];
}

interface Store {
  kind: 'session' | 'cache';
  key: string;
  route: string;
  untrusted: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeCrossRequest(source: string, options?: { file?: string }): { findings: XreqFinding[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { findings: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const stores: Store[] = [];
  const events: UnsoundEvent[] = [];
  const findings: XreqFinding[] = [];
  for (const stmt of program.body) {
    const route = topRoute(stmt);
    if (route === null) {continue;}
    collect(route.body, route.path, stores, events, file);
  }
  for (const stmt of program.body) {
    const route = topRoute(stmt);
    if (route === null) {continue;}
    readStores(route.body, route.path, stores, findings, file);
  }
  return { findings, events };
}

function topRoute(stmt: TSESTree.Statement): { path: string; body: TSESTree.Statement[] } | null {
  if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {return null;}
  const call = stmt.expression;
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return null;}
  const method = propName(callee);
  if (method !== 'get' && method !== 'post') {return null;}
  const path = call.arguments[0];
  const handler = call.arguments[1];
  if (path === undefined || path.type !== 'Literal' || typeof path.value !== 'string') {return null;}
  if (handler === undefined || (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression')) {return null;}
  if (handler.body.type !== 'BlockStatement') {return null;}
  return { path: path.value, body: handler.body.body };
}

function collect(body: readonly TSESTree.Statement[], route: string, stores: Store[], events: UnsoundEvent[], file: string): void {
  for (const stmt of body) {
    if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'AssignmentExpression') {
      const { left, right } = stmt.expression;
      if (left.type === 'MemberExpression' && isSession(left.object)) {
        const key = propName(left);
        if (key === null) {
          events.push({ kind: 'dynamic-property', file, line: lineOf(left), reason: 'dynamic session key' });
          continue;
        }
        stores.push({ kind: 'session', key, route, untrusted: isRequestSource(right) || (right.type === 'MemberExpression' && isRequestSource(right)) });
      }
    }
    if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
      const call = stmt.expression;
      const callee = stripNode(call.callee);
      if (callee.type === 'MemberExpression' && propName(callee) === 'set') {
        const key = call.arguments[0];
        const value = call.arguments[1];
        if (key !== undefined && key.type === 'Literal' && typeof key.value === 'string' && value !== undefined && value.type !== 'SpreadElement') {
          stores.push({ kind: 'cache', key: key.value, route, untrusted: isRequestSource(value) });
        } else if (key !== undefined && key.type !== 'Literal') {
          events.push({ kind: 'dynamic-property', file, line: lineOf(call), reason: 'dynamic cache key' });
        }
      }
    }
  }
}

function readStores(body: readonly TSESTree.Statement[], route: string, stores: readonly Store[], findings: XreqFinding[], file: string): void {
  for (const stmt of body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    const call = stmt.expression;
    const callee = stripNode(call.callee);
    if (callee.type !== 'MemberExpression' || (propName(callee) !== 'send' && propName(callee) !== 'write')) {continue;}
    const arg = call.arguments[0];
    if (arg === undefined || arg.type === 'SpreadElement') {continue;}
    const key = sessionKey(arg) ?? cacheKey(arg);
    if (key === null) {continue;}
    const match = stores.find((store) => store.kind === key.kind && store.key === key.key && store.untrusted);
    if (match === undefined) {continue;}
    findings.push({ file, line: lineOf(call), origin: key.kind, routes: [match.route, route] });
  }
}

function isSession(node: TSESTree.Node): boolean {
  const current = stripNode(node);
  return current.type === 'MemberExpression' && current.object.type === 'Identifier' && current.object.name === 'req' && propName(current) === 'session';
}

function sessionKey(node: TSESTree.Node): { kind: 'session'; key: string } | null {
  if (node.type !== 'MemberExpression' || !isSession(node.object)) {return null;}
  const key = propName(node);
  return key === null ? null : { kind: 'session', key };
}

function cacheKey(node: TSESTree.Node): { kind: 'cache'; key: string } | null {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression' || propName(node.callee) !== 'get') {return null;}
  const arg = node.arguments[0];
  if (arg !== undefined && arg.type === 'Literal' && typeof arg.value === 'string') {return { kind: 'cache', key: arg.value };}
  return null;
}
