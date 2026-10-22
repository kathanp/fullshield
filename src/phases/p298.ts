import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PRISMA';

export interface PrismaModel {
  name: string;
  fields: string[];
}

export interface PrismaFinding {
  file: string;
  line: number;
  sink: 'raw' | 'operator';
}

export interface KeySet {
  field: string;
  keys: string[];
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzePrisma(source: string, schema: string, options?: { file?: string }): { findings: PrismaFinding[]; models: PrismaModel[]; keySets: KeySet[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { findings: [], models: [], keySets: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const parsed = parsePrisma(schema);
  if (parsed === null) {
    return { findings: [], models: [], keySets: [], events: [{ kind: 'unresolved-import', file: 'schema.prisma', line: 1, reason: 'schema parse' }] };
  }
  const program = parseProgram(source);
  if (program === null) {return { findings: [], models: parsed, keySets: [], events: [] };}
  const findings: PrismaFinding[] = [];
  const keySets: KeySet[] = [];
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'CallExpression') {noteCall(node, findings, keySets, file);}
    if (node.type === 'TaggedTemplateExpression') {noteTag(node, findings, file);}
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range') {continue;}
      const child: unknown = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(child)) {
        for (const item of child) {if (isNode(item)) {visit(item);}}
      } else if (isNode(child)) {visit(child);}
    }
  };
  visit(program);
  return { findings, models: parsed, keySets, events: [] };
}

function noteCall(call: TSESTree.CallExpression, findings: PrismaFinding[], keySets: KeySet[], file: string): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return;}
  const name = propName(callee);
  if (name === '$queryRawUnsafe' || name === '$executeRawUnsafe' || name === 'raw') {
    const arg = call.arguments[0];
    if (arg !== undefined && tainted(arg) && !numericOnly(arg)) {findings.push({ file, line: lineOf(call), sink: 'raw' });}
    return;
  }
  if (name === 'findMany' || name === 'findFirst' || name === 'create' || name === 'update') {
    const arg = call.arguments[0];
    if (arg === undefined || arg.type !== 'ObjectExpression') {return;}
    const where = prop(arg, 'where');
    if (where !== null && where.type === 'Identifier') {findings.push({ file, line: lineOf(call), sink: 'operator' });}
    if (where !== null && where.type === 'MemberExpression' && tainted(where)) {findings.push({ file, line: lineOf(call), sink: 'operator' });}
    const data = prop(arg, 'data');
    if (data !== null && data.type === 'ObjectExpression') {
      const keys = data.properties.flatMap((item) => item.type === 'Property' && item.key.type === 'Identifier' ? [item.key.name] : []);
      if (keys.length > 0) {keySets.push({ field: 'data', keys });}
    }
  }
  if (call.callee.type === 'TaggedTemplateExpression') {return;}
}

function noteTag(node: TSESTree.TaggedTemplateExpression, findings: PrismaFinding[], file: string): void {
  const tag = stripNode(node.tag);
  const name = tag.type === 'MemberExpression' ? propName(tag) : tag.type === 'Identifier' ? tag.name : null;
  if (name !== '$queryRaw' && name !== 'sql') {return;}
  const hole = node.quasi.expressions.find((expr) => tainted(expr) && !numericOnly(expr));
  if (hole !== undefined) {findings.push({ file, line: lineOf(node), sink: 'raw' });}
}

function tainted(node: TSESTree.Node): boolean {
  if (node.type === 'MemberExpression') {
    let current: TSESTree.Node = node;
    while (current.type === 'MemberExpression') {current = current.object;}
    return current.type === 'Identifier' && (current.name === 'req' || current.name === 'request');
  }
  if (node.type === 'BinaryExpression') {return tainted(node.left) || tainted(node.right);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => tainted(expr));}
  if (node.type === 'Identifier') {return node.name === 'req' || node.name === 'request';}
  return false;
}

function numericOnly(node: TSESTree.Node): boolean {
  if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && (node.callee.name === 'Number' || node.callee.name === 'parseInt')) {return true;}
  if (node.type === 'BinaryExpression') {return numericOnly(node.left) || numericOnly(node.right);}
  return false;
}

function prop(node: TSESTree.ObjectExpression, name: string): TSESTree.Node | null {
  for (const item of node.properties) {
    if (item.type === 'Property' && item.key.type === 'Identifier' && item.key.name === name) {return item.value;}
  }
  return null;
}

function parsePrisma(schema: string): PrismaModel[] | null {
  if (schema.includes('{') && !schema.includes('}')) {return null;}
  const models: PrismaModel[] = [];
  const blocks = schema.split('model ').slice(1);
  for (const block of blocks) {
    const name = /^(\w+)/.exec(block)?.[1];
    const body = /\{([^}]*)\}/.exec(block)?.[1];
    if (name === undefined || body === undefined) {return null;}
    const fields = body.split('\n').map((line) => line.trim()).filter((line) => line.length > 0 && !line.startsWith('//') && !line.startsWith('@@')).map((line) => line.split(/\s+/)[0] ?? '').filter((field) => field.length > 0);
    models.push({ name, fields });
  }
  return models;
}

function isNode(value: unknown): value is TSESTree.Node {
  return typeof value === 'object' && value !== null && 'type' in value && typeof value.type === 'string';
}
