import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GRAPHQL';

export interface GraphqlFinding {
  file: string;
  line: number;
  route: string;
  finding: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeGraphql(source: string, options?: { file?: string }): { findings: GraphqlFinding[]; routes: string[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { findings: [], routes: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], routes: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const enums = enumFields(program);
  const findings: GraphqlFinding[] = [];
  const routes: string[] = [];
  const bag: GqlBag = { enums, findings, routes, file };
  for (const stmt of program.body) {scanResolvers(stmt, bag);}
  return { findings, routes, events: [] };
}

interface GqlBag {
  enums: ReadonlySet<string>;
  findings: GraphqlFinding[];
  routes: string[];
  file: string;
}

function scanResolvers(stmt: TSESTree.Statement, bag: GqlBag): void {
  if (stmt.type !== 'VariableDeclaration') {return;}
  for (const decl of stmt.declarations) {scanResolverDecl(decl, bag);}
}

function scanResolverDecl(decl: TSESTree.VariableDeclarator, bag: GqlBag): void {
  if (decl.id.type !== 'Identifier' || decl.id.name !== 'resolvers' || decl.init === null || decl.init.type !== 'ObjectExpression') {return;}
  for (const parent of decl.init.properties) {scanResolverType(parent, bag);}
}

function scanResolverType(parent: TSESTree.ObjectLiteralElement, bag: GqlBag): void {
  if (parent.type !== 'Property' || parent.key.type !== 'Identifier' || parent.value.type !== 'ObjectExpression') {return;}
  for (const field of parent.value.properties) {scanResolverField(parent.key.name, field, bag);}
}

function scanResolverField(parentName: string, field: TSESTree.ObjectLiteralElement, bag: GqlBag): void {
  if (field.type !== 'Property' || field.key.type !== 'Identifier') {return;}
  const route = `GRAPHQL ${parentName}.${field.key.name}`;
  bag.routes.push(route);
  const fn = resolverFn(field.value);
  if (fn === null) {return;}
  const argsName = fn.params[1]?.type === 'Identifier' ? fn.params[1].name : null;
  for (const inner of fn.body.body) {noteGraphqlQuery(inner, argsName, route, bag);}
}

function resolverFn(value: TSESTree.Node): (TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression) & { body: TSESTree.BlockStatement } | null {
  if (value.type !== 'FunctionExpression' && value.type !== 'ArrowFunctionExpression') {return null;}
  if (value.body.type !== 'BlockStatement') {return null;}
  return value as (TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression) & { body: TSESTree.BlockStatement };
}

function noteGraphqlQuery(inner: TSESTree.Statement, argsName: string | null, route: string, bag: GqlBag): void {
  const arg = queryArg(inner);
  if (arg === null || argsName === null || !usesArg(arg, argsName)) {return;}
  const fieldName = argField(arg, argsName);
  if (fieldName !== null && bag.enums.has(fieldName)) {return;}
  bag.findings.push({ file: bag.file, line: lineOf(inner), route, finding: true });
}

function queryArg(inner: TSESTree.Statement): TSESTree.Node | null {
  if (inner.type !== 'ExpressionStatement' || inner.expression.type !== 'CallExpression') {return null;}
  const callee = inner.expression.callee;
  if (callee.type !== 'MemberExpression' || propName(callee) !== 'query') {return null;}
  const arg = inner.expression.arguments[0];
  if (arg === undefined) {return null;}
  return arg;
}

function enumFields(program: TSESTree.Program): Set<string> {
  const names = new Set<string>();
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'ObjectExpression') {visitObject(node, names, visit);}
  };
  for (const stmt of program.body) {
    if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) {
        if (decl.init !== null) {visit(decl.init);}
      }
    }
  }
  return names;
}

function visitObject(node: TSESTree.ObjectExpression, names: Set<string>, visit: (node: TSESTree.Node) => void): void {
  for (const prop of node.properties) {visitEnumProp(prop, names, visit);}
}

function visitEnumProp(prop: TSESTree.ObjectLiteralElement, names: Set<string>, visit: (node: TSESTree.Node) => void): void {
  if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.value.type === 'ObjectExpression') {
    noteEnum(prop.key.name, prop.value, names);
  }
  if (prop.type === 'Property') {visit(prop.value);}
}

function noteEnum(name: string, value: TSESTree.ObjectExpression, names: Set<string>): void {
  for (const inner of value.properties) {
    if (inner.type === 'Property' && inner.key.type === 'Identifier' && inner.key.name === 'enum') {names.add(name);}
  }
}

function usesArg(node: TSESTree.Node, argsName: string): boolean {
  if (node.type === 'Identifier') {return false;}
  if (node.type === 'MemberExpression') {return node.object.type === 'Identifier' && node.object.name === argsName || (node.object.type === 'MemberExpression' && usesArg(node.object, argsName));}
  if (node.type === 'BinaryExpression') {return usesArg(node.left, argsName) || usesArg(node.right, argsName);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => usesArg(expr, argsName));}
  return false;
}

function argField(node: TSESTree.Node, argsName: string): string | null {
  if (node.type === 'MemberExpression' && node.object.type === 'Identifier' && node.object.name === argsName && node.property.type === 'Identifier') {return node.property.name;}
  if (node.type === 'BinaryExpression') {return argField(node.left, argsName) ?? argField(node.right, argsName);}
  if (node.type === 'TemplateLiteral') {
    for (const expr of node.expressions) {
      const field = argField(expr, argsName);
      if (field !== null) {return field;}
    }
  }
  return null;
}
