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
  const supported = verkey ? selected.row !== null && !selected.fallback : rows.some((row) => row.appliesTo !== undefined && satisfiesRange(options.version, row.appliesTo));
  const events = verkey ? selected.events : [];
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events, row: selected.row?.id ?? null };}
  const findings: OrmFinding[] = [];
  walkAst(program, (node) => {
    if (node.type === 'CallExpression') {noteCall(node, options.library, supported, findings, file);}
    if (node.type === 'TaggedTemplateExpression' && !supported) {return;}
  });
  return { findings, events, row: supported ? (selected.row?.id ?? rows[0]?.id ?? null) : null };
}

function noteCall(call: TSESTree.CallExpression, library: string, supported: boolean, findings: OrmFinding[], file: string): void {
  const callee = stripNode(call.callee);
  const name = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' ? propName(callee) : null;
  if (name === null) {return;}
  if ((name === 'query' || name === 'literal' || name === '$where' || name === 'raw') && call.arguments.some((arg) => arg.type !== 'SpreadElement' && tainted(arg))) {
    findings.push({ file, line: lineOf(call), library, sink: 'raw' });
    return;
  }
  if (name === 'where' && bound(call)) {return;}
  if (name === 'where' && call.arguments.some((arg) => arg.type !== 'SpreadElement' && wholeObject(arg))) {
    findings.push({ file, line: lineOf(call), library, sink: 'operator' });
    return;
  }
  if (name === 'findAll' || name === 'find' || name === 'findMany' || name === 'create') {
    const arg = call.arguments[0];
    if (arg !== undefined && arg.type === 'ObjectExpression') {
      const rawWhere = property(arg, '$where');
      if (rawWhere !== null && (wholeObject(rawWhere) || tainted(rawWhere))) {findings.push({ file, line: lineOf(call), library, sink: 'raw' });}
      const where = property(arg, 'where');
      if (where !== null && wholeObject(where)) {findings.push({ file, line: lineOf(call), library, sink: 'operator' });}
    }
  }
  if (!supported && name === 'findAll') {return;}
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
