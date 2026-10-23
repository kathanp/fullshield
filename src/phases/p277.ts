import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  isRequestSource,
  lineOf,
  parseProgram,
  propName,
  stripNode,
  walkAst,
  type SoundMode,
  type UnsoundEvent,
} from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_REFLECT';

export interface ReflectFinding {
  file: string;
  line: number;
  sinkClass: string;
}

export interface ReflectResult {
  findings: ReflectFinding[];
  events: UnsoundEvent[];
}

interface Obj {
  fields: Map<string, boolean>;
  opaque: boolean;
  forward: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeReflect(source: string, options?: { file?: string; mode?: SoundMode }): ReflectResult {
  if (!enabled()) {return { findings: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const mode = options?.mode ?? 'precise';
  const events: UnsoundEvent[] = [];
  walkAst(program, (node) => {
    if (node.type === 'WithStatement') {
      events.push({ kind: 'dynamic-property', file, line: lineOf(node), reason: 'with-statement' });
    }
    if (node.type === 'MemberExpression' && isToStringTrick(node)) {
      events.push({ kind: 'eval', file, line: lineOf(node), reason: 'function-tostring' });
    }
  });
  const state: ReflectState = {
    objects: new Map(),
    tainted: new Map(),
    findings: [],
    events,
    file,
    mode,
  };
  for (const stmt of program.body) {exec(stmt, state);}
  return { findings: state.findings, events };
}

interface ReflectState {
  objects: Map<string, Obj>;
  tainted: Map<string, boolean>;
  findings: ReflectFinding[];
  events: UnsoundEvent[];
  file: string;
  mode: SoundMode;
}

function exec(stmt: TSESTree.Statement, state: ReflectState): void {
  if (stmt.type === 'FunctionDeclaration') {execBlock(stmt.body.body, state); return;}
  if (stmt.type === 'BlockStatement') {execBlock(stmt.body, state); return;}
  if (stmt.type === 'VariableDeclaration') {execVars(stmt, state);}
  if (stmt.type === 'ExpressionStatement') {execExpr(stmt, state);}
}

function execBlock(body: readonly TSESTree.Statement[], state: ReflectState): void {
  for (const inner of body) {exec(inner, state);}
}

function execVars(stmt: TSESTree.VariableDeclaration, state: ReflectState): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type !== 'Identifier' || decl.init === null) {continue;}
    bind(decl.id.name, decl.init, state);
  }
}

function execExpr(stmt: TSESTree.ExpressionStatement, state: ReflectState): void {
  const expr = stripNode(stmt.expression);
  if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {bind(expr.left.name, expr.right, state);}
  if (expr.type === 'CallExpression') {noteCall(expr, state);}
}

function bind(name: string, init: TSESTree.Expression, state: ReflectState): void {
  const current = stripNode(init);
  if (current.type === 'ObjectExpression') {bindObject(name, current, state); return;}
  if (current.type === 'NewExpression' && current.callee.type === 'Identifier' && current.callee.name === 'Proxy') {
    bindProxy(name, current, state);
    return;
  }
  state.tainted.set(name, exprTainted(current, state.tainted, state.objects, state.mode));
}

function bindObject(name: string, current: TSESTree.ObjectExpression, state: ReflectState): void {
  const obj: Obj = { fields: new Map(), opaque: false, forward: false };
  for (const prop of current.properties) {bindField(prop, obj, state);}
  state.objects.set(name, obj);
}

function bindField(prop: TSESTree.ObjectLiteralElement, obj: Obj, state: ReflectState): void {
  if (prop.type !== 'Property' || prop.key.type !== 'Identifier' || isFnValue(prop.value)) {return;}
  obj.fields.set(prop.key.name, exprTainted(prop.value, state.tainted, state.objects, state.mode));
}

function isFnValue(node: TSESTree.Node): boolean {
  return node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression';
}

function bindProxy(name: string, current: TSESTree.NewExpression, state: ReflectState): void {
  const obj = copyProxyTarget(current.arguments[0], state.objects);
  const handler = current.arguments[1];
  if (handler !== undefined && handler.type === 'ObjectExpression' && handlerHasForwardingGet(handler)) {
    obj.opaque = false;
    obj.forward = true;
  } else {
    state.events.push({ kind: 'proxy', file: state.file, line: lineOf(current), reason: 'opaque proxy' });
  }
  state.objects.set(name, obj);
  state.tainted.set(name, proxyTaint(obj, state.mode));
}

function copyProxyTarget(target: TSESTree.CallExpressionArgument | undefined, objects: Map<string, Obj>): Obj {
  const obj: Obj = { fields: new Map(), opaque: true, forward: false };
  if (target === undefined || target.type === 'SpreadElement' || target.type !== 'Identifier') {return obj;}
  const source = objects.get(target.name);
  if (source !== undefined) {
    for (const [key, value] of source.fields) {obj.fields.set(key, value);}
  }
  return obj;
}

function proxyTaint(obj: Obj, mode: SoundMode): boolean {
  const anyField = [...obj.fields.values()].some((value) => value);
  if (obj.opaque) {return mode === 'sound' && anyField;}
  return anyField;
}

function noteCall(call: TSESTree.CallExpression, state: ReflectState): void {
  const callee = stripNode(call.callee);
  if (callee.type === 'MemberExpression' && propName(callee) === 'query') {noteQuery(call, state); return;}
  if (callee.type !== 'MemberExpression') {return;}
  noteReflect(call, callee, state);
}

function noteQuery(call: TSESTree.CallExpression, state: ReflectState): void {
  const arg = call.arguments[0];
  if (arg !== undefined && arg.type !== 'SpreadElement' && exprTainted(arg, state.tainted, state.objects, state.mode)) {
    state.findings.push({ file: state.file, line: lineOf(call), sinkClass: 'sqli' });
  }
}

function noteReflect(call: TSESTree.CallExpression, callee: TSESTree.MemberExpression, state: ReflectState): void {
  const objectName = callee.object.type === 'Identifier' ? callee.object.name : null;
  const method = propName(callee);
  if (objectName === 'Reflect' && method === 'set') {reflectSet(call, state.objects, state.tainted, state.mode); return;}
  if (objectName === 'Object' && method === 'defineProperty') {defineProperty(call, state.objects, state.tainted, state.mode);}
}

function reflectSet(call: TSESTree.CallExpression, objects: Map<string, Obj>, tainted: Map<string, boolean>, mode: SoundMode): void {
  const objArg = call.arguments[0];
  const keyArg = call.arguments[1];
  const valueArg = call.arguments[2];
  if (objArg === undefined || keyArg === undefined || valueArg === undefined) {return;}
  if (objArg.type !== 'Identifier' || keyArg.type === 'SpreadElement' || valueArg.type === 'SpreadElement') {return;}
  if (keyArg.type !== 'Literal' || typeof keyArg.value !== 'string') {return;}
  const obj = objects.get(objArg.name) ?? { fields: new Map(), opaque: false, forward: false };
  obj.fields.set(keyArg.value, exprTainted(valueArg, tainted, objects, mode));
  objects.set(objArg.name, obj);
}

function reflectGet(call: TSESTree.CallExpression, objects: ReadonlyMap<string, Obj>, mode: SoundMode): boolean {
  const objArg = call.arguments[0];
  const keyArg = call.arguments[1];
  if (objArg === undefined || keyArg === undefined || objArg.type !== 'Identifier' || keyArg.type === 'SpreadElement') {return false;}
  const obj = objects.get(objArg.name);
  if (obj === undefined) {return false;}
  if (obj.opaque) {return mode === 'sound';}
  if (keyArg.type === 'Literal' && typeof keyArg.value === 'string') {return obj.fields.get(keyArg.value) ?? false;}
  return [...obj.fields.values()].some((value) => value);
}

function defineProperty(call: TSESTree.CallExpression, objects: Map<string, Obj>, tainted: Map<string, boolean>, mode: SoundMode): void {
  const objArg = call.arguments[0];
  const keyArg = call.arguments[1];
  const desc = call.arguments[2];
  if (objArg === undefined || keyArg === undefined || desc === undefined) {return;}
  if (objArg.type !== 'Identifier' || keyArg.type !== 'Literal' || typeof keyArg.value !== 'string' || desc.type !== 'ObjectExpression') {return;}
  const obj = objects.get(objArg.name) ?? { fields: new Map(), opaque: false, forward: false };
  let value = false;
  for (const prop of desc.properties) {
    if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.key.name === 'get' && (prop.value.type === 'FunctionExpression' || prop.value.type === 'ArrowFunctionExpression')) {
      value = bodyReturnsTainted(prop.value.body, tainted, objects, mode);
    }
  }
  obj.fields.set(keyArg.value, value);
  objects.set(objArg.name, obj);
}

function exprTainted(
  node: TSESTree.Node,
  tainted: ReadonlyMap<string, boolean>,
  objects: ReadonlyMap<string, Obj>,
  mode: SoundMode,
): boolean {
  const current = stripNode(node);
  if (isRequestSource(current)) {return true;}
  if (current.type === 'Identifier') {return identTainted(current.name, tainted, objects, mode);}
  if (isIdentMember(current)) {return memberTainted(current, tainted, objects, mode);}
  if (current.type === 'CallExpression') {return callTainted(current, tainted, objects, mode);}
  if (current.type === 'BinaryExpression') {
    return exprTainted(current.left, tainted, objects, mode) || exprTainted(current.right, tainted, objects, mode);
  }
  return false;
}

function identTainted(name: string, tainted: ReadonlyMap<string, boolean>, objects: ReadonlyMap<string, Obj>, mode: SoundMode): boolean {
  const obj = objects.get(name);
  if (obj?.opaque) {return mode === 'sound' && [...obj.fields.values()].some((value) => value);}
  return tainted.get(name) ?? false;
}

function isIdentMember(node: TSESTree.Node): node is TSESTree.MemberExpression & { object: TSESTree.Identifier } {
  return node.type === 'MemberExpression' && node.object.type === 'Identifier';
}

function memberTainted(
  current: TSESTree.MemberExpression & { object: TSESTree.Identifier },
  tainted: ReadonlyMap<string, boolean>,
  objects: ReadonlyMap<string, Obj>,
  mode: SoundMode,
): boolean {
  const obj = objects.get(current.object.name);
  const field = propName(current);
  if (obj === undefined || field === null) {return exprTainted(current.object, tainted, objects, mode);}
  if (obj.opaque) {return mode === 'sound';}
  return obj.fields.get(field) ?? false;
}

function callTainted(
  current: TSESTree.CallExpression,
  tainted: ReadonlyMap<string, boolean>,
  objects: ReadonlyMap<string, Obj>,
  mode: SoundMode,
): boolean {
  const callee = stripNode(current.callee);
  if (isReflect(callee, 'get')) {return reflectGet(current, objects, mode);}
  if (isReflect(callee, 'apply')) {return reflectApply(current, tainted, objects, mode);}
  return false;
}

function isReflect(callee: TSESTree.Node, method: string): boolean {
  return callee.type === 'MemberExpression'
    && callee.object.type === 'Identifier'
    && callee.object.name === 'Reflect'
    && propName(callee) === method;
}

function reflectApply(
  current: TSESTree.CallExpression,
  tainted: ReadonlyMap<string, boolean>,
  objects: ReadonlyMap<string, Obj>,
  mode: SoundMode,
): boolean {
  const list = current.arguments[2];
  if (list === undefined || list.type !== 'ArrayExpression') {return false;}
  return list.elements.some((el) => el !== null && el.type !== 'SpreadElement' && exprTainted(el, tainted, objects, mode));
}

function bodyReturnsTainted(
  body: TSESTree.BlockStatement | TSESTree.Expression,
  tainted: ReadonlyMap<string, boolean>,
  objects: ReadonlyMap<string, Obj>,
  mode: SoundMode,
): boolean {
  if (body.type !== 'BlockStatement') {return exprTainted(body, tainted, objects, mode);}
  return body.body.some((stmt) => stmt.type === 'ReturnStatement' && stmt.argument !== null && exprTainted(stmt.argument, tainted, objects, mode));
}

function handlerHasForwardingGet(handler: TSESTree.ObjectExpression): boolean {
  return handler.properties.some((prop) => {
    if (prop.type !== 'Property' || prop.key.type !== 'Identifier' || prop.key.name !== 'get') {return false;}
    if (prop.value.type !== 'FunctionExpression' && prop.value.type !== 'ArrowFunctionExpression') {return false;}
    const params = prop.value.params.flatMap((param) => (param.type === 'Identifier' ? [param.name] : []));
    const target = params[0];
    if (target === undefined) {return false;}
    let forwards = false;
    walkAst(prop.value.body, (node) => {
      if (node.type === 'MemberExpression' && node.object.type === 'Identifier' && node.object.name === target) {forwards = true;}
    });
    return forwards;
  });
}

function isToStringTrick(node: TSESTree.MemberExpression): boolean {
  if (propName(node) !== 'toString') {return false;}
  const object = stripNode(node.object);
  return object.type === 'MemberExpression' && object.object.type === 'Identifier' && object.object.name === 'Function' && propName(object) === 'prototype';
}
