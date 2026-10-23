import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_NESTDI';

export interface NestFinding {
  file: string;
  line: number;
  route: string;
  keys: 'Unknown' | 'Finite';
}

interface FieldSafe {
  safe: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeNest(source: string, options?: { file?: string }): { findings: NestFinding[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { findings: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const dtoFields = new Map<string, Map<string, FieldSafe>>();
  const requestScoped = new Set<string>();
  const events: UnsoundEvent[] = [];
  const localClasses = new Set<string>();
  for (const stmt of program.body) {indexClass(stmt, dtoFields, requestScoped, localClasses);}
  const findings: NestFinding[] = [];
  const shared = new Map<string, boolean>();
  const nest: NestCtx = { dtoFields, localClasses, findings, events, file, shared, requestScoped };
  for (const stmt of program.body) {scanClass(stmt, nest);}
  return { findings, events };
}

interface NestCtx {
  dtoFields: Map<string, Map<string, FieldSafe>>;
  localClasses: ReadonlySet<string>;
  findings: NestFinding[];
  events: UnsoundEvent[];
  file: string;
  shared: Map<string, boolean>;
  requestScoped: ReadonlySet<string>;
}

function indexClass(
  stmt: TSESTree.Statement,
  dtoFields: Map<string, Map<string, FieldSafe>>,
  requestScoped: Set<string>,
  localClasses: Set<string>,
): void {
  if (stmt.type !== 'ClassDeclaration' || stmt.id === null) {return;}
  localClasses.add(stmt.id.name);
  if (isRequestScoped(stmt)) {requestScoped.add(stmt.id.name);}
  const fields = classFields(stmt);
  if (fields.size > 0) {dtoFields.set(stmt.id.name, fields);}
}

function classFields(stmt: TSESTree.ClassDeclaration): Map<string, FieldSafe> {
  const fields = new Map<string, FieldSafe>();
  for (const element of stmt.body.body) {
    if (element.type !== 'PropertyDefinition' || element.key.type !== 'Identifier') {continue;}
    fields.set(element.key.name, { safe: safeDecorators(element) });
  }
  return fields;
}

function safeDecorators(element: TSESTree.PropertyDefinition): boolean {
  const names = decoratorNames(element);
  return names.includes('IsInt') || names.includes('IsUUID') || names.includes('IsEnum');
}

function scanClass(stmt: TSESTree.Statement, nest: NestCtx): void {
  if (stmt.type !== 'ClassDeclaration') {return;}
  const scoped = classScoped(stmt, nest.requestScoped);
  for (const element of stmt.body.body) {scanMethod(element, scoped, nest);}
}

function classScoped(stmt: TSESTree.ClassDeclaration, requestScoped: ReadonlySet<string>): boolean {
  return stmt.id !== null && requestScoped.has(stmt.id.name) || injectedRequestScope(stmt, requestScoped);
}

function scanMethod(element: TSESTree.ClassElement, scoped: boolean, nest: NestCtx): void {
  if (element.type !== 'MethodDefinition' || element.value.type !== 'FunctionExpression') {return;}
  const route = decoratorRoute(element) ?? (element.key.type === 'Identifier' ? element.key.name : 'handler');
  const unknownPipe = hasUnknownPipe(element, nest.localClasses);
  if (unknownPipe) {nest.events.push({ kind: 'unknown-callee', file: nest.file, line: lineOf(element), reason: 'custom pipe' });}
  const env = scoped ? new Map<string, boolean>() : nest.shared;
  analyzeMethod(element.value, route, unknownPipe, env, nest);
}

function analyzeMethod(
  fn: TSESTree.FunctionExpression,
  route: string,
  unknownPipe: boolean,
  env: Map<string, boolean>,
  nest: NestCtx,
): void {
  const run: MethodRun = { params: methodParams(fn, env), env, route, unknownPipe, nest };
  for (const stmt of fn.body.body) {analyzeNestStmt(stmt, run);}
}

interface MethodRun {
  params: Map<string, string | null>;
  env: Map<string, boolean>;
  route: string;
  unknownPipe: boolean;
  nest: NestCtx;
}

function methodParams(fn: TSESTree.FunctionExpression, env: Map<string, boolean>): Map<string, string | null> {
  const params = new Map<string, string | null>();
  for (const param of fn.params) {bindParam(param, params, env);}
  return params;
}

function bindParam(param: TSESTree.Parameter, params: Map<string, string | null>, env: Map<string, boolean>): void {
  if (param.type !== 'Identifier' || !isBodyParam(param)) {return;}
  const typeName = paramTypeName(param);
  params.set(param.name, typeName);
  if (typeName === null) {env.set(param.name, true);}
}

function isBodyParam(param: TSESTree.Identifier): boolean {
  const names = decoratorNames(param);
  return names.includes('Body') || names.includes('Query') || names.includes('Param');
}

function paramTypeName(param: TSESTree.Identifier): string | null {
  const annotation = param.typeAnnotation?.typeAnnotation;
  if (annotation?.type !== 'TSTypeReference' || annotation.typeName.type !== 'Identifier') {return null;}
  return annotation.typeName.name;
}

function analyzeNestStmt(stmt: TSESTree.Statement, run: MethodRun): void {
  if (stmt.type !== 'ExpressionStatement') {return;}
  if (stmt.expression.type === 'AssignmentExpression') {noteAssign(stmt.expression, run);}
  if (stmt.expression.type === 'CallExpression') {noteNestQuery(stmt.expression, run);}
}

function noteAssign(expr: TSESTree.AssignmentExpression, run: MethodRun): void {
  const path = memberPath(expr.left);
  if (path !== null && exprTainted(expr.right, run.params, run.env)) {run.env.set(path, true);}
}

function noteNestQuery(call: TSESTree.CallExpression, run: MethodRun): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || propName(callee) !== 'query') {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  if (skipsQuery(arg, run)) {return;}
  const field = fieldUse(arg, run.params);
  run.nest.findings.push({ file: run.nest.file, line: lineOf(call), route: run.route, keys: field === null ? 'Unknown' : 'Finite' });
}

function skipsQuery(arg: TSESTree.Expression, run: MethodRun): boolean {
  const field = fieldUse(arg, run.params);
  const safe = field !== null && fieldSafe(field, run.nest.dtoFields) && !run.unknownPipe;
  if (safe) {return true;}
  if (!exprTainted(arg, run.params, run.env) && field === null) {return true;}
  if (field !== null && fieldSafe(field, run.nest.dtoFields) && !run.unknownPipe) {return true;}
  return !exprTainted(arg, run.params, run.env);
}

function fieldSafe(field: { dto: string; name: string }, dtoFields: ReadonlyMap<string, ReadonlyMap<string, FieldSafe>>): boolean {
  return dtoFields.get(field.dto)?.get(field.name)?.safe === true;
}

function fieldUse(node: TSESTree.Node, params: ReadonlyMap<string, string | null>): { dto: string; name: string } | null {
  if (node.type === 'MemberExpression' && node.object.type === 'Identifier' && node.property.type === 'Identifier') {
    const dto = params.get(node.object.name);
    if (dto !== undefined && dto !== null) {return { dto, name: node.property.name };}
  }
  if (node.type === 'BinaryExpression') {return fieldUse(node.left, params) ?? fieldUse(node.right, params);}
  return null;
}

function exprTainted(node: TSESTree.Node, params: ReadonlyMap<string, string | null>, env: ReadonlyMap<string, boolean>): boolean {
  if (node.type === 'Identifier' && (params.has(node.name) || env.get(node.name) === true)) {return true;}
  if (node.type === 'MemberExpression') {
    const path = memberPath(node);
    if (path !== null && env.get(path) === true) {return true;}
    return exprTainted(node.object, params, env);
  }
  if (node.type === 'BinaryExpression') {return exprTainted(node.left, params, env) || exprTainted(node.right, params, env);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => exprTainted(expr, params, env));}
  return false;
}

function memberPath(node: TSESTree.Node): string | null {
  if (node.type !== 'MemberExpression' || node.property.type !== 'Identifier') {return null;}
  if (node.object.type === 'MemberExpression' && node.object.property.type === 'Identifier') {
    return `${node.object.property.name}.${node.property.name}`;
  }
  return null;
}

function decoratorNames(node: { decorators?: TSESTree.Decorator[] }): string[] {
  const names: string[] = [];
  for (const decorator of node.decorators ?? []) {
    const expr = decorator.expression;
    if (expr.type === 'Identifier') {names.push(expr.name);}
    if (expr.type === 'CallExpression' && expr.callee.type === 'Identifier') {names.push(expr.callee.name);}
  }
  return names;
}

function decoratorRoute(node: TSESTree.MethodDefinition): string | null {
  for (const decorator of node.decorators ?? []) {
    const expr = decorator.expression;
    if (expr.type === 'CallExpression' && expr.callee.type === 'Identifier') {
      const arg = expr.arguments[0];
      if (arg !== undefined && arg.type === 'Literal' && typeof arg.value === 'string') {return arg.value;}
    }
  }
  return null;
}

function isRequestScoped(node: TSESTree.ClassDeclaration): boolean {
  for (const decorator of node.decorators ?? []) {
    if (decorator.expression.type !== 'CallExpression') {continue;}
    const arg = decorator.expression.arguments[0];
    if (arg === undefined || arg.type !== 'ObjectExpression') {continue;}
    for (const prop of arg.properties) {
      if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.key.name === 'scope' && prop.value.type === 'MemberExpression' && propName(prop.value) === 'REQUEST') {
        return true;
      }
    }
  }
  return false;
}

function injectedRequestScope(node: TSESTree.ClassDeclaration, requestScoped: ReadonlySet<string>): boolean {
  for (const element of node.body.body) {
    if (element.type !== 'MethodDefinition' || element.kind !== 'constructor') {continue;}
    for (const param of element.value.params) {
      if (param.type === 'TSParameterProperty' && param.parameter.type === 'Identifier') {
        const annotation = param.parameter.typeAnnotation?.typeAnnotation;
        if (annotation?.type === 'TSTypeReference' && annotation.typeName.type === 'Identifier' && requestScoped.has(annotation.typeName.name)) {return true;}
      }
    }
  }
  return false;
}

function hasUnknownPipe(node: TSESTree.MethodDefinition, localClasses: ReadonlySet<string>): boolean {
  for (const decorator of node.decorators ?? []) {
    if (decorator.expression.type !== 'CallExpression' || decorator.expression.callee.type !== 'Identifier') {continue;}
    if (decorator.expression.callee.name !== 'UsePipes') {continue;}
    const arg = decorator.expression.arguments[0];
    if (arg !== undefined && arg.type === 'Identifier' && !localClasses.has(arg.name)) {return true;}
  }
  return false;
}
