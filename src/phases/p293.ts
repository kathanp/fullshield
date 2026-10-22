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
  for (const stmt of program.body) {
    if (stmt.type !== 'ClassDeclaration' || stmt.id === null) {continue;}
    localClasses.add(stmt.id.name);
    if (isRequestScoped(stmt)) {requestScoped.add(stmt.id.name);}
    const fields = new Map<string, FieldSafe>();
    for (const element of stmt.body.body) {
      if (element.type !== 'PropertyDefinition' || element.key.type !== 'Identifier') {continue;}
      fields.set(element.key.name, { safe: decoratorNames(element).includes('IsInt') || decoratorNames(element).includes('IsUUID') || decoratorNames(element).includes('IsEnum') });
    }
    if (fields.size > 0) {dtoFields.set(stmt.id.name, fields);}
  }
  const findings: NestFinding[] = [];
  const shared = new Map<string, boolean>();
  for (const stmt of program.body) {
    if (stmt.type !== 'ClassDeclaration') {continue;}
    const scoped = stmt.id !== null && requestScoped.has(stmt.id.name) || injectedRequestScope(stmt, requestScoped);
    for (const element of stmt.body.body) {
      if (element.type !== 'MethodDefinition' || element.value.type !== 'FunctionExpression') {continue;}
      const route = decoratorRoute(element) ?? (element.key.type === 'Identifier' ? element.key.name : 'handler');
      const unknownPipe = hasUnknownPipe(element, localClasses);
      if (unknownPipe) {events.push({ kind: 'unknown-callee', file, line: lineOf(element), reason: 'custom pipe' });}
      const env = scoped ? new Map<string, boolean>() : shared;
      analyzeMethod(element.value, route, dtoFields, unknownPipe, env, findings, file);
    }
  }
  return { findings, events };
}

function analyzeMethod(
  fn: TSESTree.FunctionExpression,
  route: string,
  dtoFields: ReadonlyMap<string, ReadonlyMap<string, FieldSafe>>,
  unknownPipe: boolean,
  env: Map<string, boolean>,
  findings: NestFinding[],
  file: string,
): void {
  const params = new Map<string, string | null>();
  for (const param of fn.params) {
    if (param.type !== 'Identifier') {continue;}
    const names = decoratorNames(param);
    if (!names.includes('Body') && !names.includes('Query') && !names.includes('Param')) {continue;}
    const typeName = param.typeAnnotation?.typeAnnotation.type === 'TSTypeReference' && param.typeAnnotation.typeAnnotation.typeName.type === 'Identifier'
      ? param.typeAnnotation.typeAnnotation.typeName.name
      : null;
    params.set(param.name, typeName);
    if (typeName === null) {env.set(param.name, true);}
  }
  const body = fn.body.body;
  for (const stmt of body) {
    if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'AssignmentExpression') {
      const path = memberPath(stmt.expression.left);
      if (path !== null && exprTainted(stmt.expression.right, params, env)) {env.set(path, true);}
    }
    if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
      const call = stmt.expression;
      const callee = stripNode(call.callee);
      if (callee.type !== 'MemberExpression' || propName(callee) !== 'query') {continue;}
      const arg = call.arguments[0];
      if (arg === undefined || arg.type === 'SpreadElement') {continue;}
      const field = fieldUse(arg, params);
      if (field !== null && !unknownPipe) {
        const safe = dtoFields.get(field.dto)?.get(field.name)?.safe === true;
        if (safe) {continue;}
      }
      if (!exprTainted(arg, params, env) && field === null) {continue;}
      if (field !== null && dtoFields.get(field.dto)?.get(field.name)?.safe === true && !unknownPipe) {continue;}
      if (!exprTainted(arg, params, env)) {continue;}
      findings.push({ file, line: lineOf(call), route, keys: field === null ? 'Unknown' : 'Finite' });
    }
  }
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
