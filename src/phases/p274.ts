import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode, walkAst } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CHA';

export interface HierarchyFinding {
  file: string;
  line: number;
  resolved: string;
}

interface MethodFn {
  params: string[];
  body: TSESTree.Node;
}

interface ClassInfo {
  parent: string | null;
  methods: Map<string, MethodFn>;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeHierarchy(source: string, options?: { file?: string }): { findings: HierarchyFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const classes = new Map<string, ClassInfo>();
  const objects = new Map<string, Map<string, MethodFn>>();
  const ensure = (name: string): ClassInfo => ensureClass(classes, name);
  for (const stmt of program.body) {collectDecl(stmt, ensure, objects);}
  const points = new Map<string, string>();
  const findings: HierarchyFinding[] = [];
  for (const stmt of program.body) {execStmt(stmt, points, classes, findings, file);}
  return { findings };
}

function ensureClass(classes: Map<string, ClassInfo>, name: string): ClassInfo {
  const found = classes.get(name);
  if (found !== undefined) {return found;}
  const created: ClassInfo = { parent: null, methods: new Map() };
  classes.set(name, created);
  return created;
}

function collectDecl(
  stmt: TSESTree.Statement,
  ensure: (name: string) => ClassInfo,
  objects: Map<string, Map<string, MethodFn>>,
): void {
  if (stmt.type === 'ClassDeclaration' && stmt.id !== null) {collectClass(stmt, ensure);}
  if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {ensure(stmt.id.name);}
  if (stmt.type === 'VariableDeclaration') {collectObjects(stmt, objects);}
  if (stmt.type === 'ExpressionStatement') {notePrototype(stmt.expression, ensure, objects);}
}

function collectClass(stmt: TSESTree.ClassDeclaration, ensure: (name: string) => ClassInfo): void {
  if (stmt.id === null) {return;}
  const info = ensure(stmt.id.name);
  if (stmt.superClass !== null && stmt.superClass.type === 'Identifier') {info.parent = stmt.superClass.name;}
  for (const member of stmt.body.body) {collectMethod(member, info);}
}

function collectMethod(member: TSESTree.ClassElement, info: ClassInfo): void {
  if (member.type !== 'MethodDefinition' || member.kind !== 'method' || member.key.type !== 'Identifier') {return;}
  if (member.value.type !== 'FunctionExpression') {return;}
  info.methods.set(member.key.name, fnOf(member.value));
}

function collectObjects(stmt: TSESTree.VariableDeclaration, objects: Map<string, Map<string, MethodFn>>): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type === 'Identifier' && decl.init !== null && decl.init.type === 'ObjectExpression') {
      objects.set(decl.id.name, objectMethods(decl.init));
    }
  }
}

function fnOf(fn: TSESTree.FunctionExpression | TSESTree.FunctionDeclaration): MethodFn {
  return {
    params: fn.params.flatMap((param) => (param.type === 'Identifier' ? [param.name] : [])),
    body: fn.body,
  };
}

function objectMethods(obj: TSESTree.ObjectExpression): Map<string, MethodFn> {
  const methods = new Map<string, MethodFn>();
  for (const prop of obj.properties) {
    if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {continue;}
    if (prop.value.type === 'FunctionExpression') {methods.set(prop.key.name, fnOf(prop.value));}
  }
  return methods;
}

function notePrototype(
  expr: TSESTree.Expression,
  ensure: (name: string) => ClassInfo,
  objects: ReadonlyMap<string, Map<string, MethodFn>>,
): void {
  const node = stripNode(expr);
  noteProtoAssign(node, ensure);
  if (node.type !== 'CallExpression') {return;}
  noteProtoCall(node, ensure, objects);
}

function noteProtoAssign(node: TSESTree.Node, ensure: (name: string) => ClassInfo): void {
  if (node.type !== 'AssignmentExpression' || node.left.type !== 'MemberExpression') {return;}
  const proto = node.left.object;
  if (proto.type !== 'MemberExpression' || propName(proto) !== 'prototype' || proto.object.type !== 'Identifier') {return;}
  const method = propName(node.left);
  if (method !== null && node.right.type === 'FunctionExpression') {
    ensure(proto.object.name).methods.set(method, fnOf(node.right));
  }
}

function noteProtoCall(
  node: TSESTree.CallExpression,
  ensure: (name: string) => ClassInfo,
  objects: ReadonlyMap<string, Map<string, MethodFn>>,
): void {
  const callee = stripNode(node.callee);
  const name = calleeName(callee);
  if (name === 'inherits') {noteInherits(node, ensure);}
  if (name === 'assign') {noteAssign(node, ensure, objects);}
}

function calleeName(callee: TSESTree.Node): string | null {
  if (callee.type === 'Identifier') {return callee.name;}
  if (callee.type === 'MemberExpression') {return propName(callee);}
  return null;
}

function noteInherits(node: TSESTree.CallExpression, ensure: (name: string) => ClassInfo): void {
  if (node.arguments.length < 2) {return;}
  const sub = node.arguments[0];
  const base = node.arguments[1];
  if (sub !== undefined && base !== undefined && sub.type === 'Identifier' && base.type === 'Identifier') {
    ensure(sub.name).parent = base.name;
  }
}

function noteAssign(
  node: TSESTree.CallExpression,
  ensure: (name: string) => ClassInfo,
  objects: ReadonlyMap<string, Map<string, MethodFn>>,
): void {
  if (node.arguments.length < 2) {return;}
  const target = node.arguments[0];
  const mixin = node.arguments[1];
  if (!isPrototypeTarget(target) || mixin === undefined) {return;}
  const info = ensure(target.object.name);
  const methods = mixinMethods(mixin, objects);
  if (methods === undefined) {return;}
  for (const [key, method] of methods) {info.methods.set(key, method);}
}

function isPrototypeTarget(target: TSESTree.CallExpressionArgument | undefined): target is TSESTree.MemberExpression & { object: TSESTree.Identifier } {
  return target !== undefined
    && target.type === 'MemberExpression'
    && propName(target) === 'prototype'
    && target.object.type === 'Identifier';
}

function mixinMethods(
  mixin: TSESTree.CallExpressionArgument,
  objects: ReadonlyMap<string, Map<string, MethodFn>>,
): Map<string, MethodFn> | undefined {
  if (mixin.type === 'Identifier') {return objects.get(mixin.name);}
  if (mixin.type === 'ObjectExpression') {return objectMethods(mixin);}
  return undefined;
}

function execStmt(
  stmt: TSESTree.Statement,
  points: Map<string, string>,
  classes: ReadonlyMap<string, ClassInfo>,
  findings: HierarchyFinding[],
  file: string,
): void {
  if (stmt.type === 'VariableDeclaration') {
    for (const decl of stmt.declarations) {
      if (decl.id.type === 'Identifier' && decl.init !== null) {
        const created = newName(decl.init);
        if (created !== null) {points.set(decl.id.name, created);}
      }
    }
  }
  if (stmt.type === 'ExpressionStatement') {
    const expr = stripNode(stmt.expression);
    if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
      const created = newName(expr.right);
      if (created !== null) {points.set(expr.left.name, created);}
    }
    if (expr.type === 'CallExpression') {noteVirtual(expr, points, classes, findings, file);}
  }
  if (stmt.type === 'BlockStatement') {
    for (const inner of stmt.body) {execStmt(inner, points, classes, findings, file);}
  }
  if (stmt.type === 'FunctionDeclaration') {
    for (const inner of stmt.body.body) {execStmt(inner, points, classes, findings, file);}
  }
}

function newName(node: TSESTree.Node): string | null {
  const current = stripNode(node);
  if (current.type === 'NewExpression' && current.callee.type === 'Identifier') {return current.callee.name;}
  return null;
}

function noteVirtual(
  call: TSESTree.CallExpression,
  points: ReadonlyMap<string, string>,
  classes: ReadonlyMap<string, ClassInfo>,
  findings: HierarchyFinding[],
  file: string,
): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || callee.object.type !== 'Identifier') {return;}
  const method = propName(callee);
  const className = points.get(callee.object.name);
  if (method === null || className === undefined) {return;}
  const resolved = lookup(className, method, classes, new Set());
  if (resolved === null) {return;}
  const arg = call.arguments[0];
  const tainted = arg !== undefined && arg.type !== 'SpreadElement' && isRequestSource(arg);
  if (!tainted) {return;}
  if (!methodSinksParam(resolved.method, resolved.method.params[0])) {return;}
  findings.push({ file, line: lineOf(call), resolved: `${resolved.owner}.${method}` });
}

function lookup(
  className: string,
  method: string,
  classes: ReadonlyMap<string, ClassInfo>,
  seen: Set<string>,
): { owner: string; method: MethodFn } | null {
  if (seen.has(className)) {return null;}
  seen.add(className);
  const info = classes.get(className);
  if (info === undefined) {return null;}
  const found = info.methods.get(method);
  if (found !== undefined) {return { owner: className, method: found };}
  if (info.parent === null) {return null;}
  return lookup(info.parent, method, classes, seen);
}

function methodSinksParam(method: MethodFn, param: string | undefined): boolean {
  if (param === undefined) {return false;}
  let hit = false;
  walkAst(method.body, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression' || propName(node.callee) !== 'query') {return;}
    if (node.arguments.some((arg) => arg.type !== 'SpreadElement' && usesName(arg, param))) {hit = true;}
  });
  return hit;
}

function usesName(node: TSESTree.Node, name: string): boolean {
  if (node.type === 'Identifier') {return node.name === name;}
  if (node.type === 'BinaryExpression') {return usesName(node.left, name) || usesName(node.right, name);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => usesName(expr, name));}
  return false;
}
