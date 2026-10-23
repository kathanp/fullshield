import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CLOSURES';

export interface ClosureFinding {
  file: string;
  line: number;
  sinkClass: string;
}

export interface ClosureResult {
  findings: ClosureFinding[];
  events: UnsoundEvent[];
}

interface Cell {
  value: Val;
}

interface Closure {
  params: string[];
  body: TSESTree.BlockStatement | TSESTree.Expression;
  cells: Map<string, Cell>;
  line: number;
}

interface Val {
  taint: boolean;
  num?: number;
  arr?: Val[];
  fn?: Closure;
}

interface Escape {
  cells: Cell[];
  tainted: boolean;
  ambiguous: boolean;
  line: number;
}

const DEFER = new Set(['setTimeout', 'setImmediate', 'queueMicrotask']);

interface ClosureSinks {
  file: string;
  findings: ClosureFinding[];
  escaped: Escape[];
  deferred: Closure[];
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeClosures(source: string, options?: { file?: string }): ClosureResult {
  if (!enabled()) {return { findings: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const findings: ClosureFinding[] = [];
  const events: UnsoundEvent[] = [];
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {
      runFunction(stmt.body, stmt.params, file, findings, events);
    }
  }
  return { findings, events };
}

function runFunction(
  body: TSESTree.BlockStatement,
  params: TSESTree.Parameter[],
  file: string,
  findings: ClosureFinding[],
  events: UnsoundEvent[],
): void {
  const env = new Map<string, Cell>();
  for (const param of params) {
    if (param.type === 'Identifier') {env.set(param.name, { value: { taint: false } });}
  }
  hoist(body, env);
  const escaped: Escape[] = [];
  const deferred: Closure[] = [];
  const sinks: ClosureSinks = { file, findings, escaped, deferred };
  execBlock(body.body, env, sinks);
  for (const fn of deferred) {callClosure(fn, sinks);}
  for (const escape of escaped) {
    if (!escape.tainted) {continue;}
    findings.push({ file, line: escape.line, sinkClass: 'sqli' });
    if (escape.ambiguous) {
      events.push({ kind: 'unknown-callee', file, line: escape.line, reason: 'closure-order' });
    }
  }
}

function hoist(body: TSESTree.BlockStatement, env: Map<string, Cell>): void {
  const visit = (stmts: readonly TSESTree.Statement[]): void => {
    for (const stmt of stmts) {hoistStmt(stmt, env, visit);}
  };
  visit(body.body);
}

function hoistStmt(
  stmt: TSESTree.Statement,
  env: Map<string, Cell>,
  visit: (stmts: readonly TSESTree.Statement[]) => void,
): void {
  if (stmt.type === 'VariableDeclaration' && stmt.kind === 'var') {hoistVars(stmt, env);}
  if (isVarFor(stmt)) {hoistVars(stmt.init, env);}
  if (stmt.type === 'BlockStatement') {visit(stmt.body);}
  if (stmt.type === 'ForStatement' && stmt.body.type === 'BlockStatement') {visit(stmt.body.body);}
}

function isVarFor(stmt: TSESTree.Statement): stmt is TSESTree.ForStatement & { init: TSESTree.VariableDeclaration } {
  return stmt.type === 'ForStatement' && stmt.init !== null && stmt.init.type === 'VariableDeclaration' && stmt.init.kind === 'var';
}

function hoistVars(stmt: TSESTree.VariableDeclaration, env: Map<string, Cell>): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type === 'Identifier' && !env.has(decl.id.name)) {env.set(decl.id.name, { value: { taint: false } });}
  }
}

function execBlock(stmts: readonly TSESTree.Statement[], env: Map<string, Cell>, sinks: ClosureSinks): void {
  for (const stmt of stmts) {execStmt(stmt, env, sinks);}
}

function execStmt(stmt: TSESTree.Statement, env: Map<string, Cell>, sinks: ClosureSinks): void {
  if (stmt.type === 'BlockStatement') {execBlock(stmt.body, env, sinks); return;}
  if (stmt.type === 'VariableDeclaration') {execVars(stmt, env, sinks); return;}
  if (stmt.type === 'ExpressionStatement') {execExpr(stmt, env, sinks); return;}
  if (stmt.type === 'ForStatement') {execFor(stmt, env, sinks); return;}
  if (stmt.type === 'ReturnStatement' && stmt.argument !== null) {evalExpr(stmt.argument, env, sinks);}
}

function execVars(stmt: TSESTree.VariableDeclaration, env: Map<string, Cell>, sinks: ClosureSinks): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type !== 'Identifier') {continue;}
    const cell = env.get(decl.id.name) ?? { value: { taint: false } };
    if (decl.init !== null) {cell.value = evalExpr(decl.init, env, sinks);}
    env.set(decl.id.name, cell);
  }
}

function execExpr(stmt: TSESTree.ExpressionStatement, env: Map<string, Cell>, sinks: ClosureSinks): void {
  const expr = stripNode(stmt.expression);
  if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
    assignCell(expr.left.name, expr.right, env, sinks);
    return;
  }
  evalExpr(expr, env, sinks);
}

function assignCell(name: string, right: TSESTree.Node, env: Map<string, Cell>, sinks: ClosureSinks): void {
  const cell = env.get(name) ?? { value: { taint: false } };
  cell.value = evalExpr(right, env, sinks);
  env.set(name, cell);
  markEscapes(cell, sinks.escaped);
}

function execFor(stmt: TSESTree.ForStatement, env: Map<string, Cell>, sinks: ClosureSinks): void {
  const letLoop = isLetInit(stmt.init);
  if (stmt.init !== null && stmt.init.type === 'VariableDeclaration' && !letLoop) {execStmt(stmt.init, env, sinks);}
  let index = initialIndex(stmt.init);
  for (let n = 0; n < 8; n += 1) {
    if (index >= loopLimit(stmt.test)) {break;}
    const iter = bindLoopIndex(stmt, env, letLoop, index);
    execLoopBody(stmt, letLoop ? iter : env, sinks);
    index += 1;
  }
}

function isLetInit(init: TSESTree.ForStatement['init']): boolean {
  return init !== null && init.type === 'VariableDeclaration' && init.kind !== 'var';
}

function bindLoopIndex(stmt: TSESTree.ForStatement, env: Map<string, Cell>, letLoop: boolean, index: number): Map<string, Cell> {
  const iter = new Map(env);
  if (stmt.init === null || stmt.init.type !== 'VariableDeclaration') {return iter;}
  if (letLoop) {bindLetIndex(stmt.init, iter, index);}
  else {bindVarIndex(stmt.init, env, index);}
  return iter;
}

function bindLetIndex(init: TSESTree.VariableDeclaration, iter: Map<string, Cell>, index: number): void {
  for (const decl of init.declarations) {
    if (decl.id.type === 'Identifier') {iter.set(decl.id.name, { value: { taint: false, num: index } });}
  }
}

function bindVarIndex(init: TSESTree.VariableDeclaration, env: Map<string, Cell>, index: number): void {
  for (const decl of init.declarations) {
    if (decl.id.type !== 'Identifier') {continue;}
    const cell = env.get(decl.id.name);
    if (cell !== undefined) {cell.value = { taint: false, num: index };}
  }
}

function execLoopBody(stmt: TSESTree.ForStatement, env: Map<string, Cell>, sinks: ClosureSinks): void {
  if (stmt.body.type === 'BlockStatement') {execBlock(stmt.body.body, env, sinks); return;}
  execStmt(stmt.body, env, sinks);
}

function initialIndex(init: TSESTree.ForStatement['init']): number {
  if (init !== null && init.type === 'VariableDeclaration') {
    const decl = init.declarations[0];
    if (decl !== undefined && decl.init !== null && decl.init.type === 'Literal' && typeof decl.init.value === 'number') {
      return decl.init.value;
    }
  }
  return 0;
}

function loopLimit(test: TSESTree.ForStatement['test']): number {
  if (test !== null && test.type === 'BinaryExpression' && test.right.type === 'Literal' && typeof test.right.value === 'number') {
    return test.right.value;
  }
  return 1;
}

function evalExpr(node: TSESTree.Node, env: Map<string, Cell>, sinks: ClosureSinks): Val {
  const current = stripNode(node);
  if (current.type === 'Literal') {return evalLiteral(current);}
  if (isRequestSource(current)) {return { taint: true };}
  if (current.type === 'Identifier') {return env.get(current.name)?.value ?? { taint: false };}
  if (current.type === 'ArrayExpression') {return evalArray(current, env, sinks);}
  if (current.type === 'FunctionExpression' || current.type === 'ArrowFunctionExpression') {
    return { taint: false, fn: capture(current, env) };
  }
  if (current.type === 'ConditionalExpression') {return evalCond(current, env, sinks);}
  if (current.type === 'BinaryExpression') {return evalBinary(current, env, sinks);}
  if (current.type === 'UpdateExpression' && current.argument.type === 'Identifier') {return evalUpdate(current.argument.name, env);}
  if (current.type === 'CallExpression') {return evalCall(current, env, sinks);}
  if (current.type === 'MemberExpression') {return evalMember(current, env, sinks);}
  return { taint: false };
}

function evalLiteral(current: TSESTree.Literal): Val {
  if (typeof current.value === 'number') {return { taint: false, num: current.value };}
  return { taint: false };
}

function evalArray(current: TSESTree.ArrayExpression, env: Map<string, Cell>, sinks: ClosureSinks): Val {
  return { taint: false, arr: current.elements.flatMap((el) => (el === null || el.type === 'SpreadElement' ? [] : [evalExpr(el, env, sinks)])) };
}

function evalCond(current: TSESTree.ConditionalExpression, env: Map<string, Cell>, sinks: ClosureSinks): Val {
  const test = evalExpr(current.test, env, sinks);
  const branch = truthy(test) ? current.consequent : current.alternate;
  return evalExpr(branch, env, sinks);
}

function evalBinary(current: TSESTree.BinaryExpression, env: Map<string, Cell>, sinks: ClosureSinks): Val {
  const left = evalExpr(current.left, env, sinks);
  const right = evalExpr(current.right, env, sinks);
  if (current.operator === '===') {return { taint: false, num: left.num !== undefined && left.num === right.num ? 1 : 0 };}
  if (left.taint || right.taint) {return { taint: true };}
  return { taint: false };
}

function evalUpdate(name: string, env: Map<string, Cell>): Val {
  const cell = env.get(name);
  const num = (cell?.value.num ?? 0) + 1;
  if (cell !== undefined) {cell.value = { taint: false, num };}
  return { taint: false, num };
}

function evalMember(current: TSESTree.MemberExpression, env: Map<string, Cell>, sinks: ClosureSinks): Val {
  const object = evalExpr(current.object, env, sinks);
  if (current.computed && current.property.type === 'Literal' && typeof current.property.value === 'number') {
    return object.arr?.[current.property.value] ?? { taint: false };
  }
  if (object.taint) {return { taint: true };}
  return { taint: false };
}

function truthy(value: Val): boolean {
  if (value.num !== undefined) {return value.num !== 0;}
  return value.taint;
}

function capture(fn: TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression, env: ReadonlyMap<string, Cell>): Closure {
  const params = new Set(fn.params.flatMap((param) => (param.type === 'Identifier' ? [param.name] : [])));
  const cells = new Map<string, Cell>();
  const locals = new Set<string>(params);
  const bodyNode: TSESTree.Node = fn.body;
  collectFree(bodyNode, locals, env, cells);
  return { params: [...params], body: fn.body, cells, line: lineOf(fn) };
}

function collectFree(node: TSESTree.Node, locals: Set<string>, env: ReadonlyMap<string, Cell>, cells: Map<string, Cell>): void {
  noteFreeIdent(node, locals, env, cells);
  if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') {locals.add(node.id.name);}
  for (const key of Object.keys(node)) {collectFreeKey(node, key, locals, env, cells);}
}

function noteFreeIdent(node: TSESTree.Node, locals: Set<string>, env: ReadonlyMap<string, Cell>, cells: Map<string, Cell>): void {
  if (node.type !== 'Identifier' || locals.has(node.name)) {return;}
  const cell = env.get(node.name);
  if (cell !== undefined) {cells.set(node.name, cell);}
}

function collectFreeKey(
  node: TSESTree.Node,
  key: string,
  locals: Set<string>,
  env: ReadonlyMap<string, Cell>,
  cells: Map<string, Cell>,
): void {
  if (key === 'loc' || key === 'range' || key === 'parent') {return;}
  if (isNestedFn(node) && key !== 'body') {return;}
  const child: unknown = (node as unknown as Record<string, unknown>)[key];
  collectFreeChild(child, locals, env, cells);
}

function isNestedFn(node: TSESTree.Node): boolean {
  return node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression';
}

function collectFreeChild(child: unknown, locals: Set<string>, env: ReadonlyMap<string, Cell>, cells: Map<string, Cell>): void {
  if (Array.isArray(child)) {
    for (const item of child) {
      if (isNode(item)) {collectFree(item, locals, env, cells);}
    }
    return;
  }
  if (isNode(child)) {collectFree(child, locals, env, cells);}
}

function isNode(value: unknown): value is TSESTree.Node {
  return typeof value === 'object' && value !== null && 'type' in value && typeof value.type === 'string';
}

function evalCall(call: TSESTree.CallExpression, env: Map<string, Cell>, sinks: ClosureSinks): Val {
  const callee = stripNode(call.callee);
  const args = call.arguments.flatMap((arg) => (arg.type === 'SpreadElement' ? [] : [evalExpr(arg, env, sinks)]));
  if (callee.type === 'MemberExpression') {return evalMemberCall(call, callee, args, env, sinks);}
  if (callee.type === 'Identifier') {return evalIdentCall(call, callee.name, args, env, sinks);}
  return { taint: args.some((arg) => arg.taint) };
}

function evalMemberCall(
  call: TSESTree.CallExpression,
  callee: TSESTree.MemberExpression,
  args: Val[],
  env: Map<string, Cell>,
  sinks: ClosureSinks,
): Val {
  const object = evalExpr(callee.object, env, sinks);
  const name = propName(callee);
  if (name === 'query') {return noteQuery(call, args, sinks);}
  if (name === 'push' && object.arr !== undefined && args[0] !== undefined) {
    object.arr.push(args[0]);
    return { taint: false };
  }
  noteIndexedCall(callee, object, sinks);
  return { taint: args.some((arg) => arg.taint) };
}

function noteQuery(call: TSESTree.CallExpression, args: readonly Val[], sinks: ClosureSinks): Val {
  if (args.some((arg) => arg.taint)) {sinks.findings.push({ file: sinks.file, line: lineOf(call), sinkClass: 'sqli' });}
  return { taint: false };
}

function noteIndexedCall(callee: TSESTree.MemberExpression, object: Val, sinks: ClosureSinks): void {
  if (!callee.computed || callee.property.type !== 'Literal' || typeof callee.property.value !== 'number') {return;}
  const item = object.arr?.[callee.property.value];
  if (item?.fn !== undefined) {callClosure(item.fn, sinks);}
}

function evalIdentCall(call: TSESTree.CallExpression, name: string, args: Val[], env: Map<string, Cell>, sinks: ClosureSinks): Val {
  const local = env.get(name)?.value.fn;
  if (local !== undefined) {
    callClosure(local, sinks);
    return { taint: false };
  }
  if (DEFER.has(name)) {return deferClosures(args, sinks);}
  recordEscapes(call, args, sinks);
  return { taint: args.some((arg) => arg.taint) };
}

function deferClosures(args: readonly Val[], sinks: ClosureSinks): Val {
  for (const arg of args) {
    if (arg.fn !== undefined) {sinks.deferred.push(arg.fn);}
  }
  return { taint: false };
}

function recordEscapes(call: TSESTree.CallExpression, args: readonly Val[], sinks: ClosureSinks): void {
  const closures = args.flatMap((arg) => (arg.fn !== undefined ? [arg.fn] : []));
  for (const fn of closures) {
    const cells = [...fn.cells.values()];
    sinks.escaped.push({
      cells,
      tainted: cells.some((cell) => cell.value.taint),
      ambiguous: false,
      line: lineOf(call),
    });
  }
}

function callClosure(fn: Closure, sinks: ClosureSinks): void {
  const env = new Map(fn.cells);
  if (fn.body.type === 'BlockStatement') {execBlock(fn.body.body, env, sinks);}
  else {evalExpr(fn.body, env, sinks);}
}

function markEscapes(cell: Cell, escaped: Escape[]): void {
  for (const escape of escaped) {
    if (!escape.cells.includes(cell)) {continue;}
    escape.ambiguous = true;
    if (cell.value.taint) {escape.tainted = true;}
  }
}
