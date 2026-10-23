import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode } from './p271.js';
import { abstractExpression, labelsOf, type AbstractString, type CharClass, type Segment } from './p278.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SQLCTX';

export type SqlContext = 'quoted-literal' | 'numeric' | 'identifier' | 'keyword' | 'whole-query' | 'fallback';

export interface SqlToken {
  kind: 'text' | 'hole';
  text: string;
  holeContext?: SqlContext;
}

export interface SqlFinding {
  file: string;
  line: number;
  sqlContext: SqlContext;
  template: string;
  message: string;
}

export interface SqlQuery {
  line: number;
  tokens: SqlToken[];
  findings: SqlFinding[];
}

const CLIENTS = new Set(['db', 'pool', 'client', 'conn', 'connection', 'knex', 'sequelize', 'prisma', 'sqlite', 'mysql', 'pg']);

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function sqlLexer(value: AbstractString): SqlToken[] {
  const tokens: SqlToken[] = [];
  let state: 'code' | 'sq' | 'dq' = 'code';
  let preceding = '';
  for (const seg of value.segments) {
    if (seg.kind === 'literal') {
      for (const ch of seg.text) {
        tokens.push({ kind: 'text', text: ch });
        if (state === 'code' && ch === "'") {state = 'sq';}
        else if (state === 'code' && ch === '"') {state = 'dq';}
        else if (state === 'sq' && ch === "'") {state = 'code';}
        else if (state === 'dq' && ch === '"') {state = 'code';}
        else if (state === 'code') {preceding += ch;}
      }
      continue;
    }
    tokens.push({ kind: 'hole', text: holeText(seg), holeContext: holeContext(state, preceding, value) });
    if (state === 'code') {preceding += ' ? ';}
  }
  return tokens;
}

export function classifySqlValue(value: AbstractString, options?: { dialectKnown?: boolean }): { tokens: SqlToken[]; findings: SqlFinding[] } {
  if (!enabled()) {return { tokens: [], findings: [] };}
  const tokens = sqlLexer(value);
  const dialectKnown = options?.dialectKnown ?? true;
  const findings: SqlFinding[] = [];
  const template = renderTemplate(value);
  for (const token of tokens) {
    if (token.kind !== 'hole' || token.holeContext === undefined) {continue;}
    const context = dialectKnown ? token.holeContext : 'fallback';
    if (!shouldReport(context, value, token)) {continue;}
    findings.push({
      file: 'inline.js',
      line: 1,
      sqlContext: context,
      template,
      message: context === 'identifier'
        ? 'parameterization cannot fix this; an allowlist is required'
        : `sql hole in ${context}`,
    });
  }
  return { tokens, findings };
}

export function analyzeSql(source: string, options?: { file?: string }): { findings: SqlFinding[]; queries: SqlQuery[] } {
  if (!enabled()) {return { findings: [], queries: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], queries: [] };}
  const file = options?.file ?? 'inline.js';
  const findings: SqlFinding[] = [];
  const queries: SqlQuery[] = [];
  const bag: SqlWalk = { file, findings, queries, walk: () => undefined };
  bag.walk = (stmts, env) => {
    for (const stmt of stmts) {walkSql(stmt, env, bag);}
  };
  bag.walk(program.body, new Map());
  return { findings, queries };
}

interface SqlWalk {
  file: string;
  findings: SqlFinding[];
  queries: SqlQuery[];
  walk: (stmts: readonly TSESTree.Statement[], env: Map<string, AbstractString>) => void;
}

function walkSql(stmt: TSESTree.Statement, env: Map<string, AbstractString>, bag: SqlWalk): void {
  if (stmt.type === 'FunctionDeclaration') {bag.walk(stmt.body.body, new Map()); return;}
  if (stmt.type === 'BlockStatement') {bag.walk(stmt.body, env); return;}
  if (stmt.type === 'IfStatement') {walkSqlIf(stmt, env, bag); return;}
  if (stmt.type === 'VariableDeclaration') {bindSqlVars(stmt, env); return;}
  if (stmt.type === 'ExpressionStatement') {walkSqlExpr(stmt, env, bag);}
}

function walkSqlIf(stmt: TSESTree.IfStatement, env: Map<string, AbstractString>, bag: SqlWalk): void {
  bag.walk(stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent], env);
  if (stmt.alternate !== null) {
    bag.walk(stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate], env);
  }
}

function bindSqlVars(stmt: TSESTree.VariableDeclaration, env: Map<string, AbstractString>): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, abstractExpression(decl.init, env));}
  }
}

function walkSqlExpr(stmt: TSESTree.ExpressionStatement, env: Map<string, AbstractString>, bag: SqlWalk): void {
  const expr = stripNode(stmt.expression);
  if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
    env.set(expr.left.name, abstractExpression(expr.right, env));
  }
  if (expr.type === 'CallExpression') {noteQuery(expr, env, bag.file, bag.findings, bag.queries);}
}

function noteQuery(
  call: TSESTree.CallExpression,
  env: ReadonlyMap<string, AbstractString>,
  file: string,
  findings: SqlFinding[],
  queries: SqlQuery[],
): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || (propName(callee) !== 'query' && propName(callee) !== 'execute')) {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  const value = abstractExpression(arg, env);
  if (labelsOf(value).length === 0) {return;}
  const dialectKnown = callee.object.type === 'Identifier' && CLIENTS.has(callee.object.name);
  const classified = classifySqlValue(value, { dialectKnown });
  const queryFindings = classified.findings.map((finding) => ({ ...finding, file, line: lineOf(call) }));
  findings.push(...queryFindings);
  queries.push({ line: lineOf(call), tokens: classified.tokens, findings: queryFindings });
}

function holeText(seg: Segment): string {
  if (seg.kind === 'literal') {return seg.text;}
  return `?{${seg.labels.join(',')}}`;
}

function renderTemplate(value: AbstractString): string {
  return value.segments.map((seg) => (seg.kind === 'literal' ? seg.text : holeText(seg))).join('');
}

function holeContext(state: 'code' | 'sq' | 'dq', preceding: string, value: AbstractString): SqlContext {
  if (state !== 'code') {return 'quoted-literal';}
  const significant = value.segments.some((seg) => seg.kind === 'literal' && seg.text.trim() !== '');
  if (!significant) {return 'whole-query';}
  if (/;\s*$/.test(preceding)) {return 'whole-query';}
  if (/(?:order\s+by|group\s+by)\s*$/i.test(preceding.trim())) {return 'identifier';}
  if (/(?:^|[\s,(])(?:from|join|into|update|table|select)\s+$/i.test(preceding)) {return 'identifier';}
  if (/(?:=|<>|!=|<=|>=|<|>)\s*$/.test(preceding)) {return 'numeric';}
  return 'keyword';
}

function shouldReport(context: SqlContext, value: AbstractString, token: SqlToken): boolean {
  const charClass = classNear(value, token);
  if (context === 'fallback' || context === 'identifier' || context === 'keyword' || context === 'whole-query') {return true;}
  if (context === 'quoted-literal') {return !excludesQuote(charClass);}
  return charClass !== 'digits' && charClass !== 'numeric';
}

function classNear(value: AbstractString, token: SqlToken): CharClass | 'unknown' {
  const hole = value.segments.find((seg) => seg.kind !== 'literal' && holeText(seg) === token.text);
  if (hole === undefined || hole.kind === 'literal') {return 'any';}
  if (hole.kind === 'unknown') {return 'any';}
  return hole.charClass;
}

function excludesQuote(charClass: CharClass | 'unknown'): boolean {
  return charClass === 'no-quote' || charClass === 'digits' || charClass === 'numeric' || charClass === 'letters' || charClass === 'no-dash';
}
