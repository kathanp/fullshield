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
  execBlock(body.body, env, file, findings, escaped, deferred);
  for (const fn of deferred) {callClosure(fn, file, findings, escaped, deferred);}
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
    for (const stmt of stmts) {
      if (stmt.type === 'VariableDeclaration' && stmt.kind === 'var') {
        for (const decl of stmt.declarations) {
          if (decl.id.type === 'Identifier' && !env.has(decl.id.name)) {env.set(decl.id.name, { value: { taint: false } });}
        }
      }
      if (stmt.type === 'ForStatement' && stmt.init !== null && stmt.init.type === 'VariableDeclaration' && stmt.init.kind === 'var') {
        for (const decl of stmt.init.declarations) {
          if (decl.id.type === 'Identifier' && !env.has(decl.id.name)) {env.set(decl.id.name, { value: { taint: false } });}
        }
      }
      if (stmt.type === 'BlockStatement') {visit(stmt.body);}
      if (stmt.type === 'ForStatement' && stmt.body.type === 'BlockStatement') {visit(stmt.body.body);}
    }
  };
  visit(body.body);
}

function execBlock(
  stmts: readonly TSESTree.Statement[],
  env: Map<string, Cell>,
  file: string,
  findings: ClosureFinding[],
  escaped: Escape[],
  deferred: Closure[],
): void {
  for (const stmt of stmts) {execStmt(stmt, env, file, findings, escaped, deferred);}
}

function execStmt(
  stmt: TSESTree.Statement,
  env: Map<string, Cell>,
  file: string,
  findings: ClosureFinding[],
  escaped: Escape[],
  deferred: Closure[],
): void {
  if (stmt.type === 'BlockStatement') {
    execBlock(stmt.body, env, file, findings, escaped, deferred);
    return;
  }
  if (stmt.type === 'VariableDeclaration') {
    for (const decl of stmt.declarations) {
      if (decl.id.type !== 'Identifier') {continue;}
      const cell = env.get(decl.id.name) ?? { value: { taint: false } };
      if (decl.init !== null) {cell.value = evalExpr(decl.init, env, file, findings, escaped, deferred);}
      env.set(decl.id.name, cell);
    }
    return;
  }
  if (stmt.type === 'ExpressionStatement') {
    const expr = stripNode(stmt.expression);
    if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
      const cell = env.get(expr.left.name) ?? { value: { taint: false } };
      cell.value = evalExpr(expr.right, env, file, findings, escaped, deferred);
      env.set(expr.left.name, cell);
      markEscapes(cell, escaped);
      return;
    }
    evalExpr(expr, env, file, findings, escaped, deferred);
    return;
  }
  if (stmt.type === 'ForStatement') {execFor(stmt, env, file, findings, escaped, deferred); return;}
  if (stmt.type === 'ReturnStatement' && stmt.argument !== null) {
    evalExpr(stmt.argument, env, file, findings, escaped, deferred);
  }
}

function execFor(
  stmt: TSESTree.ForStatement,
  env: Map<string, Cell>,
  file: string,
  findings: ClosureFinding[],
  escaped: Escape[],
  deferred: Closure[],
): void {
  const letLoop = stmt.init !== null && stmt.init.type === 'VariableDeclaration' && stmt.init.kind !== 'var';
  if (stmt.init !== null && stmt.init.type === 'VariableDeclaration' && !letLoop) {
    execStmt(stmt.init, env, file, findings, escaped, deferred);
  }
  let index = initialIndex(stmt.init);
  for (let n = 0; n < 8; n += 1) {
    if (index >= loopLimit(stmt.test)) {break;}
    const iter = new Map(env);
    if (letLoop && stmt.init !== null && stmt.init.type === 'VariableDeclaration') {
      for (const decl of stmt.init.declarations) {
        if (decl.id.type === 'Identifier') {iter.set(decl.id.name, { value: { taint: false, num: index } });}
      }
    } else if (stmt.init !== null && stmt.init.type === 'VariableDeclaration') {
      for (const decl of stmt.init.declarations) {
        if (decl.id.type === 'Identifier') {
          const cell = env.get(decl.id.name);
          if (cell !== undefined) {cell.value = { taint: false, num: index };}
        }
      }
    }
    if (stmt.body.type === 'BlockStatement') {execBlock(stmt.body.body, letLoop ? iter : env, file, findings, escaped, deferred);}
    else {execStmt(stmt.body, letLoop ? iter : env, file, findings, escaped, deferred);}
    index += 1;
  }
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

function evalExpr(
  node: TSESTree.Node,
  env: Map<string, Cell>,
  file: string,
  findings: ClosureFinding[],
  escaped: Escape[],
  deferred: Closure[],
): Val {
  const current = stripNode(node);
  if (current.type === 'Literal') {
    if (typeof current.value === 'number') {return { taint: false, num: current.value };}
    return { taint: false };
  }
  if (isRequestSource(current)) {return { taint: true };}
  if (current.type === 'Identifier') {return env.get(current.name)?.value ?? { taint: false };}
  if (current.type === 'ArrayExpression') {
    return { taint: false, arr: current.elements.flatMap((el) => (el === null || el.type === 'SpreadElement' ? [] : [evalExpr(el, env, file, findings, escaped, deferred)])) };
  }
  if (current.type === 'FunctionExpression' || current.type === 'ArrowFunctionExpression') {
    return { taint: false, fn: capture(current, env) };
  }
  if (current.type === 'ConditionalExpression') {
    const test = evalExpr(current.test, env, file, findings, escaped, deferred);
    const branch = truthy(test) ? current.consequent : current.alternate;
    return evalExpr(branch, env, file, findings, escaped, deferred);
  }
  if (current.type === 'BinaryExpression') {
    const left = evalExpr(current.left, env, file, findings, escaped, deferred);
    const right = evalExpr(current.right, env, file, findings, escaped, deferred);
    if (current.operator === '===') {return { taint: false, num: left.num !== undefined && left.num === right.num ? 1 : 0 };}
    if (left.taint || right.taint) {return { taint: true };}
    return { taint: false };
  }
  if (current.type === 'UpdateExpression' && current.argument.type === 'Identifier') {
    const cell = env.get(current.argument.name);
    const num = (cell?.value.num ?? 0) + 1;
    if (cell !== undefined) {cell.value = { taint: false, num };}
    return { taint: false, num };
  }
  if (current.type === 'CallExpression') {return evalCall(current, env, file, findings, escaped, deferred);}
  if (current.type === 'MemberExpression') {
    const object = evalExpr(current.object, env, file, findings, escaped, deferred);
    if (current.computed && current.property.type === 'Literal' && typeof current.property.value === 'number') {
      return object.arr?.[current.property.value] ?? { taint: false };
    }
    if (object.taint) {return { taint: true };}
  }
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
  if (node.type === 'Identifier' && !locals.has(node.name)) {
    const cell = env.get(node.name);
    if (cell !== undefined) {cells.set(node.name, cell);}
  }
  if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') {locals.add(node.id.name);}
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'range' || key === 'parent') {continue;}
    if ((node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') && key !== 'body') {continue;}
    const child: unknown = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (isNode(item)) {collectFree(item, locals, env, cells);}
      }
    } else if (isNode(child)) {
      collectFree(child, locals, env, cells);
    }
  }
}

function isNode(value: unknown): value is TSESTree.Node {
  return typeof value === 'object' && value !== null && 'type' in value && typeof value.type === 'string';
}

function evalCall(
  call: TSESTree.CallExpression,
  env: Map<string, Cell>,
  file: string,
  findings: ClosureFinding[],
  escaped: Escape[],
  deferred: Closure[],
): Val {
  const callee = stripNode(call.callee);
  const args = call.arguments.flatMap((arg) => (arg.type === 'SpreadElement' ? [] : [evalExpr(arg, env, file, findings, escaped, deferred)]));
  if (callee.type === 'MemberExpression') {
    const object = evalExpr(callee.object, env, file, findings, escaped, deferred);
    const name = propName(callee);
    if (name === 'query') {
      if (args.some((arg) => arg.taint)) {findings.push({ file, line: lineOf(call), sinkClass: 'sqli' });}
      return { taint: false };
    }
    if (name === 'push' && object.arr !== undefined && args[0] !== undefined) {
      object.arr.push(args[0]);
      return { taint: false };
    }
    if (callee.computed && callee.property.type === 'Literal' && typeof callee.property.value === 'number') {
      const item = object.arr?.[callee.property.value];
      if (item?.fn !== undefined) {callClosure(item.fn, file, findings, escaped, deferred);}
    }
    return { taint: args.some((arg) => arg.taint) };
  }
  if (callee.type === 'Identifier') {
    const local = env.get(callee.name)?.value.fn;
    if (local !== undefined) {
      callClosure(local, file, findings, escaped, deferred);
      return { taint: false };
    }
    if (DEFER.has(callee.name)) {
      for (const arg of args) {
        if (arg.fn !== undefined) {deferred.push(arg.fn);}
      }
      return { taint: false };
    }
    const closures = args.flatMap((arg) => (arg.fn !== undefined ? [arg.fn] : []));
    if (closures.length > 0) {
      for (const fn of closures) {
        const cells = [...fn.cells.values()];
        escaped.push({
          cells,
          tainted: cells.some((cell) => cell.value.taint),
          ambiguous: false,
          line: lineOf(call),
        });
      }
    }
  }
  return { taint: args.some((arg) => arg.taint) };
}

function callClosure(
  fn: Closure,
  file: string,
  findings: ClosureFinding[],
  escaped: Escape[],
  deferred: Closure[],
): void {
  const env = new Map(fn.cells);
  if (fn.body.type === 'BlockStatement') {execBlock(fn.body.body, env, file, findings, escaped, deferred);}
  else {evalExpr(fn.body, env, file, findings, escaped, deferred);}
}

function markEscapes(cell: Cell, escaped: Escape[]): void {
  for (const escape of escaped) {
    if (!escape.cells.includes(cell)) {continue;}
    escape.ambiguous = true;
    if (cell.value.taint) {escape.tainted = true;}
  }
}
