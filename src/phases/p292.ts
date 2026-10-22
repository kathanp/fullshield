import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FASTIFYSCHEMA';

export interface SchemaFinding {
  file: string;
  line: number;
  field: string;
  coerceTypes: boolean;
}

interface FieldTransfer {
  safe: boolean;
  unknown: string | null;
}

const KNOWN = new Set(['type', 'properties', 'required', 'pattern', 'enum', '$ref', '$id', 'items', 'additionalProperties']);

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeFastifySchema(source: string, options?: { file?: string }): { findings: SchemaFinding[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { findings: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const schemas = new Map<string, TSESTree.Node>();
  const findings: SchemaFinding[] = [];
  const events: UnsoundEvent[] = [];
  for (const stmt of program.body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    const call = stmt.expression;
    const callee = stripNode(call.callee);
    if (callee.type === 'MemberExpression' && propName(callee) === 'addSchema') {
      const arg = call.arguments[0];
      if (arg !== undefined && arg.type === 'ObjectExpression') {
        const id = stringProp(arg, '$id');
        if (id !== null) {schemas.set(id, arg);}
      }
    }
  }
  for (const stmt of program.body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    noteRoute(stmt.expression, schemas, findings, events, file);
  }
  return { findings, events };
}

function noteRoute(
  call: TSESTree.CallExpression,
  schemas: ReadonlyMap<string, TSESTree.Node>,
  findings: SchemaFinding[],
  events: UnsoundEvent[],
  file: string,
): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return;}
  const method = propName(callee);
  if (method !== 'get' && method !== 'post' && method !== 'route') {return;}
  const options = call.arguments.find((arg) => arg.type === 'ObjectExpression');
  const handler = [...call.arguments].reverse().find((arg) => arg.type === 'ArrowFunctionExpression' || arg.type === 'FunctionExpression');
  if (options === undefined || options.type !== 'ObjectExpression' || handler === undefined) {return;}
  const schemaNode = propNode(options, 'schema');
  const coerceTypes = boolProp(options, 'coerceTypes');
  const fields = new Map<string, FieldTransfer>();
  if (schemaNode !== null && schemaNode.type === 'ObjectExpression') {
    for (const section of ['body', 'querystring', 'params', 'headers']) {
      const sectionNode = propNode(schemaNode, section);
      if (sectionNode !== null) {collectFields(sectionNode, schemas, fields, events, file);}
    }
  }
  if (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression') {return;}
  const body = handler.body.type === 'BlockStatement' ? handler.body.body : [];
  for (const stmt of body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    const sink = stmt.expression;
    const sinkCallee = stripNode(sink.callee);
    if (sinkCallee.type !== 'MemberExpression' || propName(sinkCallee) !== 'query') {continue;}
    const arg = sink.arguments[0];
    if (arg === undefined || arg.type !== 'MemberExpression' || arg.property.type !== 'Identifier') {continue;}
    const field = arg.property.name;
    const transfer = fields.get(field);
    if (transfer?.unknown !== null && transfer?.unknown !== undefined) {
      events.push({ kind: 'unknown-callee', file, line: lineOf(arg), reason: transfer.unknown });
    }
    if (transfer?.safe === true) {continue;}
    findings.push({ file, line: lineOf(sink), field, coerceTypes });
  }
}

function collectFields(
  node: TSESTree.Node,
  schemas: ReadonlyMap<string, TSESTree.Node>,
  fields: Map<string, FieldTransfer>,
  events: UnsoundEvent[],
  file: string,
): void {
  const resolved = resolveRef(node, schemas);
  if (resolved.type !== 'ObjectExpression') {return;}
  const unknown = unknownKeyword(resolved);
  if (unknown !== null) {events.push({ kind: 'unknown-callee', file, line: lineOf(resolved), reason: unknown });}
  const properties = propNode(resolved, 'properties');
  if (properties === null || properties.type !== 'ObjectExpression') {
    return;
  }
  for (const prop of properties.properties) {
    if (prop.type !== 'Property') {continue;}
    const name = prop.key.type === 'Identifier' ? prop.key.name : prop.key.type === 'Literal' && typeof prop.key.value === 'string' ? prop.key.value : null;
    if (name === null) {continue;}
    const value = resolveRef(prop.value, schemas);
    const fieldUnknown = value.type === 'ObjectExpression' ? unknownKeyword(value) : null;
    fields.set(name, { safe: isSafe(value), unknown: fieldUnknown });
  }
}

function resolveRef(node: TSESTree.Node, schemas: ReadonlyMap<string, TSESTree.Node>): TSESTree.Node {
  if (node.type !== 'ObjectExpression') {return node;}
  const ref = stringProp(node, '$ref');
  if (ref === null) {return node;}
  return schemas.get(ref.replace(/#$/, '')) ?? node;
}

function isSafe(node: TSESTree.Node): boolean {
  if (node.type !== 'ObjectExpression') {return false;}
  const type = stringProp(node, 'type');
  if (type === 'integer' || type === 'number' || type === 'boolean') {return true;}
  if (propNode(node, 'enum')?.type === 'ArrayExpression') {return true;}
  const pattern = stringProp(node, 'pattern');
  if (pattern !== null && anchoredSafe(pattern)) {return true;}
  return false;
}

function anchoredSafe(pattern: string): boolean {
  if (!pattern.startsWith('^') || !pattern.endsWith('$')) {return false;}
  const body = pattern.slice(1, -1);
  return body === 'd+' || body === '\\d+' || body === '[0-9]+' || body === '[a-zA-Z]+' || body === '[a-z]+';
}

function unknownKeyword(node: TSESTree.ObjectExpression): string | null {
  for (const prop of node.properties) {
    if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {continue;}
    if (!KNOWN.has(prop.key.name)) {return prop.key.name;}
  }
  return null;
}

function propNode(node: TSESTree.ObjectExpression, name: string): TSESTree.Node | null {
  for (const prop of node.properties) {
    if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.key.name === name) {return prop.value;}
  }
  return null;
}

function stringProp(node: TSESTree.ObjectExpression, name: string): string | null {
  const value = propNode(node, name);
  return value !== null && value.type === 'Literal' && typeof value.value === 'string' ? value.value : null;
}

function boolProp(node: TSESTree.ObjectExpression, name: string): boolean {
  const value = propNode(node, name);
  return value !== null && value.type === 'Literal' && value.value === true;
}
