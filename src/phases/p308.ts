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
  const state: ScopeState = {
    hooks: rootHooks,
    decorators: rootDecorators,
    routes,
    locals,
    events,
    file,
    breakScope: false,
  };
  for (const stmt of program.body) {applyTop(stmt, state);}
  return { routes, events };
}

interface ScopeState {
  hooks: string[];
  decorators: Map<string, string>;
  routes: ScopeRoute[];
  locals: ReadonlyMap<string, TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression>;
  events: UnsoundEvent[];
  file: string;
  breakScope: boolean;
}

function applyTop(stmt: TSESTree.Statement, state: ScopeState): void {
  if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {return;}
  applyCall(stmt.expression, state);
}

function applyCall(call: TSESTree.CallExpression, state: ScopeState): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return;}
  const name = propName(callee);
  if (name === 'addHook') {state.hooks.push('auth'); return;}
  if (name === 'decorate') {noteDecorate(call, state); return;}
  if (name === 'get' || name === 'post') {noteRoute(call, state); return;}
  if (name === 'register') {noteRegister(call, state);}
}

function noteDecorate(call: TSESTree.CallExpression, state: ScopeState): void {
  const key = call.arguments[0];
  const value = call.arguments[1];
  if (key !== undefined && key.type === 'Literal' && typeof key.value === 'string' && value !== undefined && value.type === 'Identifier') {
    state.decorators.set(key.value, value.name);
  }
}

function noteRoute(call: TSESTree.CallExpression, state: ScopeState): void {
  const path = call.arguments[0];
  if (path === undefined || path.type !== 'Literal' || typeof path.value !== 'string') {return;}
  const decorator = state.decorators.get('user') ?? null;
  state.routes.push({ path: path.value, covered: state.hooks.length > 0 || state.breakScope, decorator });
}

function noteRegister(call: TSESTree.CallExpression, state: ScopeState): void {
  const plugin = call.arguments[0];
  if (plugin === undefined) {return;}
  const resolved = resolvePlugin(plugin, state.locals);
  if (resolved.dynamic) {
    state.events.push({ kind: 'unknown-callee', file: state.file, line: 1, reason: resolved.reason });
  }
  const broken = resolved.scopeBreak || resolved.dynamic;
  const child: ScopeState = {
    ...state,
    hooks: broken ? state.hooks : [],
    decorators: new Map(state.decorators),
    breakScope: broken,
  };
  walkPlugin(resolved.fn, child, broken ? state.hooks : child.hooks);
}

function walkPlugin(
  fn: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression | null,
  child: ScopeState,
  hooks: string[],
): void {
  if (fn === null || fn.body.type !== 'BlockStatement') {return;}
  for (const stmt of fn.body.body) {
    if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
      applyCall(stmt.expression, { ...child, hooks });
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
