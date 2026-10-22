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
  const objects = new Map<string, Obj>();
  const findings: ReflectFinding[] = [];
  const tainted = new Map<string, boolean>();
  for (const stmt of program.body) {exec(stmt, objects, tainted, findings, events, file, mode);}
  return { findings, events };
}

function exec(
  stmt: TSESTree.Statement,
  objects: Map<string, Obj>,
  tainted: Map<string, boolean>,
  findings: ReflectFinding[],
  events: UnsoundEvent[],
  file: string,
  mode: SoundMode,
): void {
  if (stmt.type === 'FunctionDeclaration') {
    for (const inner of stmt.body.body) {exec(inner, objects, tainted, findings, events, file, mode);}
    return;
  }
  if (stmt.type === 'BlockStatement') {
    for (const inner of stmt.body) {exec(inner, objects, tainted, findings, events, file, mode);}
    return;
  }
  if (stmt.type === 'VariableDeclaration') {
    for (const decl of stmt.declarations) {
      if (decl.id.type !== 'Identifier' || decl.init === null) {continue;}
      bind(decl.id.name, decl.init, objects, tainted, events, file, mode);
    }
  }
  if (stmt.type === 'ExpressionStatement') {
    const expr = stripNode(stmt.expression);
    if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
      bind(expr.left.name, expr.right, objects, tainted, events, file, mode);
    }
    if (expr.type === 'CallExpression') {noteCall(expr, objects, tainted, findings, file, mode);}
  }
}

function bind(
  name: string,
  init: TSESTree.Expression,
  objects: Map<string, Obj>,
  tainted: Map<string, boolean>,
  events: UnsoundEvent[],
  file: string,
  mode: SoundMode,
): void {
  const current = stripNode(init);
  if (current.type === 'ObjectExpression') {
    const obj: Obj = { fields: new Map(), opaque: false, forward: false };
    for (const prop of current.properties) {
      if (prop.type !== 'Property' || prop.key.type !== 'Identifier' || prop.value.type === 'FunctionExpression' || prop.value.type === 'ArrowFunctionExpression') {continue;}
      obj.fields.set(prop.key.name, exprTainted(prop.value, tainted, objects, mode));
    }
    objects.set(name, obj);
    return;
  }
  if (current.type === 'NewExpression' && current.callee.type === 'Identifier' && current.callee.name === 'Proxy') {
    const handler = current.arguments[1];
    const target = current.arguments[0];
    const obj: Obj = { fields: new Map(), opaque: true, forward: false };
    if (target !== undefined && target.type !== 'SpreadElement' && target.type === 'Identifier') {
      const source = objects.get(target.name);
      if (source !== undefined) {
        for (const [key, value] of source.fields) {obj.fields.set(key, value);}
      }
    }
    if (handler !== undefined && handler.type === 'ObjectExpression' && handlerHasForwardingGet(handler)) {
      obj.opaque = false;
      obj.forward = true;
    } else {
      events.push({ kind: 'proxy', file, line: lineOf(current), reason: 'opaque proxy' });
    }
    objects.set(name, obj);
    tainted.set(name, obj.opaque ? mode === 'sound' && [...obj.fields.values()].some((value) => value) : [...obj.fields.values()].some((value) => value));
    return;
  }
  tainted.set(name, exprTainted(current, tainted, objects, mode));
}

function noteCall(
  call: TSESTree.CallExpression,
  objects: Map<string, Obj>,
  tainted: Map<string, boolean>,
  findings: ReflectFinding[],
  file: string,
  mode: SoundMode,
): void {
  const callee = stripNode(call.callee);
  if (callee.type === 'MemberExpression' && propName(callee) === 'query') {
    const arg = call.arguments[0];
    if (arg !== undefined && arg.type !== 'SpreadElement' && exprTainted(arg, tainted, objects, mode)) {
      findings.push({ file, line: lineOf(call), sinkClass: 'sqli' });
    }
    return;
  }
  if (callee.type !== 'MemberExpression') {return;}
  const objectName = callee.object.type === 'Identifier' ? callee.object.name : null;
  const method = propName(callee);
  if (objectName === 'Reflect' && method === 'set') {reflectSet(call, objects, tainted, mode); return;}
  if (objectName === 'Object' && method === 'defineProperty') {defineProperty(call, objects, tainted, mode);}
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
  if (current.type === 'Identifier') {
    const obj = objects.get(current.name);
    if (obj?.opaque) {return mode === 'sound' && [...obj.fields.values()].some((value) => value);}
    return tainted.get(current.name) ?? false;
  }
  if (current.type === 'MemberExpression' && current.object.type === 'Identifier') {
    const obj = objects.get(current.object.name);
    const field = propName(current);
    if (obj === undefined || field === null) {return exprTainted(current.object, tainted, objects, mode);}
    if (obj.opaque) {return mode === 'sound';}
    return obj.fields.get(field) ?? false;
  }
  if (current.type === 'CallExpression') {
    const callee = stripNode(current.callee);
    if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier' && callee.object.name === 'Reflect' && propName(callee) === 'get') {
      return reflectGet(current, objects, mode);
    }
    if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier' && callee.object.name === 'Reflect' && propName(callee) === 'apply') {
      const list = current.arguments[2];
      if (list !== undefined && list.type === 'ArrayExpression') {
        return list.elements.some((el) => el !== null && el.type !== 'SpreadElement' && exprTainted(el, tainted, objects, mode));
      }
    }
  }
  if (current.type === 'BinaryExpression') {
    return exprTainted(current.left, tainted, objects, mode) || exprTainted(current.right, tainted, objects, mode);
  }
  return false;
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
