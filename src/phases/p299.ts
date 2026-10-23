import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, walkAst, type UnsoundEvent } from './p271.js';
import { satisfiesRange, selectRow, type ModelRow } from './p310.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ORM2';

export interface OrmFinding {
  file: string;
  line: number;
  library: string;
  sink: 'raw' | 'operator';
}

const DEFAULT_ROWS: Record<string, ModelRow[]> = {
  sequelize: [{ id: 'sequelize-6', appliesTo: '>=6 <7' }],
  typeorm: [{ id: 'typeorm-0.3', appliesTo: '>=0.3 <0.4' }],
  mongoose: [{ id: 'mongoose-8', appliesTo: '>=8 <9' }],
  drizzle: [{ id: 'drizzle-0.29', appliesTo: '>=0.29 <1' }],
};

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeOrm(source: string, options: { library: string; version: string; file?: string; packagePath?: string; rows?: readonly ModelRow[] }): { findings: OrmFinding[]; events: UnsoundEvent[]; row: string | null } {
  if (!enabled()) {return { findings: [], events: [], row: null };}
  const file = options.file ?? 'inline.js';
  const rows = options.rows ?? DEFAULT_ROWS[options.library] ?? [];
  const packagePath = options.packagePath ?? options.library;
  const selected = selectRow(rows, options.version, packagePath);
  const verkey = process.env.FULLSHIELD_EXPERIMENTAL_VERKEY === '1';
  const supported = ormSupported(verkey, selected, rows, options.version);
  const events = verkey ? selected.events : [];
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events, row: selected.row?.id ?? null };}
  const findings: OrmFinding[] = [];
  walkAst(program, (node) => {visitOrm(node, options.library, supported, findings, file);});
  return { findings, events, row: supportedRow(supported, selected.row?.id, rows) };
}

function ormSupported(verkey: boolean, selected: { row: ModelRow | null; fallback: boolean }, rows: readonly ModelRow[], version: string): boolean {
  if (verkey) {return selected.row !== null && !selected.fallback;}
  return rows.some((row) => row.appliesTo !== undefined && satisfiesRange(version, row.appliesTo));
}

function supportedRow(supported: boolean, selectedId: string | undefined, rows: readonly ModelRow[]): string | null {
  if (!supported) {return null;}
  return selectedId ?? rows[0]?.id ?? null;
}

function visitOrm(node: TSESTree.Node, library: string, supported: boolean, findings: OrmFinding[], file: string): void {
  if (node.type === 'CallExpression') {noteCall(node, library, supported, findings, file);}
}

function noteCall(call: TSESTree.CallExpression, library: string, supported: boolean, findings: OrmFinding[], file: string): void {
  const name = calleeName(stripNode(call.callee));
  if (name === null) {return;}
  if (isRawSink(name) && hasTaintedArg(call)) {findings.push({ file, line: lineOf(call), library, sink: 'raw' }); return;}
  if (name === 'where' && bound(call)) {return;}
  if (name === 'where' && hasWholeArg(call)) {findings.push({ file, line: lineOf(call), library, sink: 'operator' }); return;}
  if (isFinder(name)) {noteFinder(call, library, findings, file);}
  if (!supported && name === 'findAll') {return;}
}

function calleeName(callee: TSESTree.Node): string | null {
  if (callee.type === 'Identifier') {return callee.name;}
  if (callee.type === 'MemberExpression') {return propName(callee);}
  return null;
}

function isRawSink(name: string): boolean {
  return name === 'query' || name === 'literal' || name === '$where' || name === 'raw';
}

function isFinder(name: string): boolean {
  return name === 'findAll' || name === 'find' || name === 'findMany' || name === 'create';
}

function hasTaintedArg(call: TSESTree.CallExpression): boolean {
  return call.arguments.some((arg) => arg.type !== 'SpreadElement' && tainted(arg));
}

function hasWholeArg(call: TSESTree.CallExpression): boolean {
  return call.arguments.some((arg) => arg.type !== 'SpreadElement' && wholeObject(arg));
}

function noteFinder(call: TSESTree.CallExpression, library: string, findings: OrmFinding[], file: string): void {
  const arg = call.arguments[0];
  if (arg === undefined || arg.type !== 'ObjectExpression') {return;}
  const rawWhere = property(arg, '$where');
  if (rawWhere !== null && (wholeObject(rawWhere) || tainted(rawWhere))) {findings.push({ file, line: lineOf(call), library, sink: 'raw' });}
  const where = property(arg, 'where');
  if (where !== null && wholeObject(where)) {findings.push({ file, line: lineOf(call), library, sink: 'operator' });}
}

function bound(call: TSESTree.CallExpression): boolean {
  const sql = call.arguments[0];
  return call.arguments.length >= 2 && sql !== undefined && sql.type === 'Literal' && typeof sql.value === 'string' && (sql.value.includes('?') || sql.value.includes('$'));
}

function wholeObject(node: TSESTree.Node): boolean {
  if (node.type === 'Identifier') {return node.name !== 'undefined';}
  if (node.type === 'MemberExpression') {
    let current: TSESTree.Node = node;
    while (current.type === 'MemberExpression') {current = current.object;}
    return current.type === 'Identifier' && (current.name === 'req' || current.name === 'request');
  }
  return false;
}

function tainted(node: TSESTree.Node): boolean {
  if (node.type === 'Literal') {return false;}
  if (node.type === 'Identifier') {return true;}
  if (node.type === 'MemberExpression') {return wholeObject(node) || tainted(node.object);}
  if (node.type === 'BinaryExpression') {return tainted(node.left) || tainted(node.right);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => tainted(expr));}
  return false;
}

function property(node: TSESTree.ObjectExpression, name: string): TSESTree.Node | null {
  for (const prop of node.properties) {
    if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.key.name === name) {return prop.value;}
  }
  return null;
}
