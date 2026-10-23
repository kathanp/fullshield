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
  for (const stmt of program.body) {indexSchema(stmt, schemas);}
  for (const stmt of program.body) {noteTop(stmt, schemas, findings, events, file);}
  return { findings, events };
}

function indexSchema(stmt: TSESTree.Statement, schemas: Map<string, TSESTree.Node>): void {
  const call = topCall(stmt);
  if (call === null) {return;}
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || propName(callee) !== 'addSchema') {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type !== 'ObjectExpression') {return;}
  const id = stringProp(arg, '$id');
  if (id !== null) {schemas.set(id, arg);}
}

function noteTop(
  stmt: TSESTree.Statement,
  schemas: ReadonlyMap<string, TSESTree.Node>,
  findings: SchemaFinding[],
  events: UnsoundEvent[],
  file: string,
): void {
  const call = topCall(stmt);
  if (call === null) {return;}
  noteRoute(call, schemas, findings, events, file);
}

function topCall(stmt: TSESTree.Statement): TSESTree.CallExpression | null {
  if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {return null;}
  return stmt.expression;
}

function noteRoute(
  call: TSESTree.CallExpression,
  schemas: ReadonlyMap<string, TSESTree.Node>,
  findings: SchemaFinding[],
  events: UnsoundEvent[],
  file: string,
): void {
  const found = routeParts(call);
  if (found === null) {return;}
  const fields = schemaFields(found.options, schemas, events, file);
  const body = found.handler.body.type === 'BlockStatement' ? found.handler.body.body : [];
  const out: SchemaOut = { findings, events, file };
  for (const stmt of body) {noteSchemaSink(stmt, fields, found.coerceTypes, out);}
}

interface SchemaOut {
  findings: SchemaFinding[];
  events: UnsoundEvent[];
  file: string;
}

function routeParts(call: TSESTree.CallExpression): { options: TSESTree.ObjectExpression; handler: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression; coerceTypes: boolean } | null {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return null;}
  const method = propName(callee);
  if (method !== 'get' && method !== 'post' && method !== 'route') {return null;}
  const options = call.arguments.find((arg) => arg.type === 'ObjectExpression');
  const handler = [...call.arguments].reverse().find((arg) => arg.type === 'ArrowFunctionExpression' || arg.type === 'FunctionExpression');
  if (options === undefined || options.type !== 'ObjectExpression' || handler === undefined) {return null;}
  if (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression') {return null;}
  return { options, handler, coerceTypes: boolProp(options, 'coerceTypes') };
}

function schemaFields(
  options: TSESTree.ObjectExpression,
  schemas: ReadonlyMap<string, TSESTree.Node>,
  events: UnsoundEvent[],
  file: string,
): Map<string, FieldTransfer> {
  const fields = new Map<string, FieldTransfer>();
  const schemaNode = propNode(options, 'schema');
  if (schemaNode === null || schemaNode.type !== 'ObjectExpression') {return fields;}
  for (const section of ['body', 'querystring', 'params', 'headers']) {
    const sectionNode = propNode(schemaNode, section);
    if (sectionNode !== null) {collectFields(sectionNode, schemas, fields, events, file);}
  }
  return fields;
}

function noteSchemaSink(
  stmt: TSESTree.Statement,
  fields: ReadonlyMap<string, FieldTransfer>,
  coerceTypes: boolean,
  out: SchemaOut,
): void {
  const field = queryField(stmt);
  if (field === null) {return;}
  const transfer = fields.get(field.name);
  if (transfer?.unknown !== null && transfer?.unknown !== undefined) {
    out.events.push({ kind: 'unknown-callee', file: out.file, line: lineOf(field.arg), reason: transfer.unknown });
  }
  if (transfer?.safe === true) {return;}
  out.findings.push({ file: out.file, line: lineOf(field.sink), field: field.name, coerceTypes });
}

function queryField(stmt: TSESTree.Statement): { sink: TSESTree.CallExpression; arg: TSESTree.MemberExpression; name: string } | null {
  if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {return null;}
  const sink = stmt.expression;
  const sinkCallee = stripNode(sink.callee);
  if (sinkCallee.type !== 'MemberExpression' || propName(sinkCallee) !== 'query') {return null;}
  const arg = sink.arguments[0];
  if (arg === undefined || arg.type !== 'MemberExpression' || arg.property.type !== 'Identifier') {return null;}
  return { sink, arg, name: arg.property.name };
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
