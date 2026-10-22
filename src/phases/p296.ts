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
  for (const stmt of program.body) {
    if (stmt.type !== 'VariableDeclaration') {continue;}
    for (const decl of stmt.declarations) {
      if (decl.id.type !== 'Identifier' || decl.init === null || decl.init.type !== 'ObjectExpression') {continue;}
      if (decl.id.name !== 'resolvers') {continue;}
      for (const parent of decl.init.properties) {
        if (parent.type !== 'Property' || parent.key.type !== 'Identifier' || parent.value.type !== 'ObjectExpression') {continue;}
        for (const field of parent.value.properties) {
          if (field.type !== 'Property' || field.key.type !== 'Identifier') {continue;}
          const route = `GRAPHQL ${parent.key.name}.${field.key.name}`;
          routes.push(route);
          const fn = field.value.type === 'FunctionExpression' || field.value.type === 'ArrowFunctionExpression' ? field.value : null;
          if (fn === null || fn.body.type !== 'BlockStatement') {continue;}
          const argsName = fn.params[1]?.type === 'Identifier' ? fn.params[1].name : null;
          for (const inner of fn.body.body) {
            if (inner.type !== 'ExpressionStatement' || inner.expression.type !== 'CallExpression') {continue;}
            const callee = inner.expression.callee;
            if (callee.type !== 'MemberExpression' || propName(callee) !== 'query') {continue;}
            const arg = inner.expression.arguments[0];
            if (arg === undefined || argsName === null || !usesArg(arg, argsName)) {continue;}
            const fieldName = argField(arg, argsName);
            if (fieldName !== null && enums.has(fieldName)) {continue;}
            findings.push({ file, line: lineOf(inner), route, finding: true });
          }
        }
      }
    }
  }
  return { findings, routes, events: [] };
}

function enumFields(program: TSESTree.Program): Set<string> {
  const names = new Set<string>();
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'ObjectExpression') {
      for (const prop of node.properties) {
        if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.value.type === 'ObjectExpression') {
          for (const inner of prop.value.properties) {
            if (inner.type === 'Property' && inner.key.type === 'Identifier' && inner.key.name === 'enum') {names.add(prop.key.name);}
          }
        }
        if (prop.type === 'Property') {visit(prop.value);}
      }
    }
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
