import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { parseProgram, propName, stripNode, walkAst, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FASTIFYSCOPE';

export interface ScopeRoute {
  path: string;
  covered: boolean;
  decorator: string | null;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeFastifyScope(source: string, options?: { file?: string }): { routes: ScopeRoute[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { routes: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { routes: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const events: UnsoundEvent[] = [];
  const locals = localFunctions(program);
  const routes: ScopeRoute[] = [];
  const rootHooks: string[] = [];
  const rootDecorators = new Map<string, string>();
  for (const stmt of program.body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    applyCall(stmt.expression, rootHooks, rootDecorators, routes, locals, events, file, false);
  }
  return { routes, events };
}

function applyCall(
  call: TSESTree.CallExpression,
  hooks: string[],
  decorators: Map<string, string>,
  routes: ScopeRoute[],
  locals: ReadonlyMap<string, TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression>,
  events: UnsoundEvent[],
  file: string,
  breakScope: boolean,
): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return;}
  const name = propName(callee);
  if (name === 'addHook') {
    hooks.push('auth');
    return;
  }
  if (name === 'decorate') {
    const key = call.arguments[0];
    const value = call.arguments[1];
    if (key !== undefined && key.type === 'Literal' && typeof key.value === 'string' && value !== undefined && value.type === 'Identifier') {
      decorators.set(key.value, value.name);
    }
    return;
  }
  if (name === 'get' || name === 'post') {
    const path = call.arguments[0];
    if (path !== undefined && path.type === 'Literal' && typeof path.value === 'string') {
      const decorator = decorators.get('user') ?? null;
      routes.push({ path: path.value, covered: hooks.length > 0 || breakScope, decorator });
    }
    return;
  }
  if (name !== 'register') {return;}
  const plugin = call.arguments[0];
  if (plugin === undefined) {return;}
  const resolved = resolvePlugin(plugin, locals);
  if (resolved.dynamic) {events.push({ kind: 'unknown-callee', file, line: 1, reason: resolved.reason });}
  const childHooks = resolved.scopeBreak || resolved.dynamic ? hooks : [];
  const childDecorators = new Map(decorators);
  if (resolved.fn !== null && resolved.fn.body.type === 'BlockStatement') {
    for (const stmt of resolved.fn.body.body) {
      if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
        applyCall(stmt.expression, resolved.scopeBreak || resolved.dynamic ? hooks : childHooks, childDecorators, routes, locals, events, file, resolved.scopeBreak || resolved.dynamic);
      }
    }
  }
}

function resolvePlugin(
  node: TSESTree.Node,
  locals: ReadonlyMap<string, TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression>,
): { fn: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression | null; scopeBreak: boolean; dynamic: boolean; reason: string } {
  if (node.type === 'Identifier') {
    const fn = locals.get(node.name) ?? null;
    return { fn, scopeBreak: false, dynamic: fn === null, reason: 'dynamic plugin' };
  }
  if (node.type === 'CallExpression') {
    const callee = stripNode(node.callee);
    const wrapped = node.arguments[0];
    const scopeBreak = callee.type === 'Identifier' && callee.name === 'fp';
    const conditional = callee.type === 'ConditionalExpression' || node.callee.type === 'ConditionalExpression';
    if (wrapped === undefined) {return { fn: null, scopeBreak: true, dynamic: true, reason: 'computed fastify-plugin' };}
    const inner = resolvePlugin(wrapped, locals);
    return { fn: inner.fn, scopeBreak: scopeBreak || inner.scopeBreak || conditional, dynamic: conditional || inner.dynamic, reason: conditional ? 'computed fastify-plugin' : inner.reason };
  }
  if (node.type === 'ConditionalExpression') {
    return { fn: null, scopeBreak: true, dynamic: true, reason: 'computed fastify-plugin' };
  }
  if (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression') {
    return { fn: node, scopeBreak: false, dynamic: false, reason: '' };
  }
  return { fn: null, scopeBreak: true, dynamic: true, reason: 'dynamic plugin' };
}

function localFunctions(program: TSESTree.Program): Map<string, TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression> {
  const locals = new Map<string, TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression>();
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {locals.set(stmt.id.name, stmt);}
  }
  walkAst(program, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id !== null) {locals.set(node.id.name, node);}
  });
  return locals;
}
