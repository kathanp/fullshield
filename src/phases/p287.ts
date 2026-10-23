import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_STORED';

export interface StoredFinding {
  file: string;
  line: number;
  origin: 'stored';
  confidence: 'medium';
  severity: 'medium';
  sinkClass: 'sqli' | 'xss' | 'cmdi' | 'ssti';
}

interface Bind {
  stored: boolean;
}

const READS = new Set(['find', 'findOne', 'findMany', 'findById', 'findAll', 'get']);

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeStored(source: string, options?: { file?: string }): { findings: StoredFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const findings: StoredFinding[] = [];
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration') {execBlock(stmt.body.body, new Map(), findings, file);}
  }
  return { findings };
}

function execBlock(stmts: readonly TSESTree.Statement[], env: Map<string, Bind>, findings: StoredFinding[], file: string): void {
  for (const stmt of stmts) {
    if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) {
        if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, { stored: isRead(decl.init) });}
      }
    }
    if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
      noteSink(stmt.expression, env, findings, file);
    }
    if (stmt.type === 'BlockStatement') {execBlock(stmt.body, env, findings, file);}
    if (stmt.type === 'IfStatement') {
      execBlock(stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent], env, findings, file);
    }
  }
}

function noteSink(call: TSESTree.CallExpression, env: ReadonlyMap<string, Bind>, findings: StoredFinding[], file: string): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return;}
  const name = propName(callee);
  const sink = sinkClass(name);
  if (sink === null || name === null) {return;}
  if (parameterized(call)) {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement' || !usesStored(arg, env)) {return;}
  findings.push({ file, line: lineOf(call), origin: 'stored', confidence: 'medium', severity: 'medium', sinkClass: sink });
}

function isRead(node: TSESTree.Node): boolean {
  const current = stripNode(node);
  if (current.type !== 'CallExpression' || current.callee.type !== 'MemberExpression') {return false;}
  const name = propName(current.callee) ?? '';
  if (READS.has(name) || name.startsWith('find')) {return true;}
  if (name === 'get') {return true;}
  if (name === 'query') {
    const arg = current.arguments[0];
    return arg !== undefined && arg.type !== 'SpreadElement' && !usesRequest(arg);
  }
  return false;
}

function usesStored(node: TSESTree.Node, env: ReadonlyMap<string, Bind>): boolean {
  if (node.type === 'Identifier') {return env.get(node.name)?.stored === true;}
  if (node.type === 'MemberExpression') {return usesStored(node.object, env);}
  if (node.type === 'BinaryExpression') {return usesStored(node.left, env) || usesStored(node.right, env);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => usesStored(expr, env));}
  return false;
}

function usesRequest(node: TSESTree.Node): boolean {
  if (isRequestSource(node)) {return true;}
  if (node.type === 'BinaryExpression') {return usesRequest(node.left) || usesRequest(node.right);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => usesRequest(expr));}
  return false;
}

function parameterized(call: TSESTree.CallExpression): boolean {
  if (call.arguments.length < 2) {return false;}
  const sql = call.arguments[0];
  if (sql === undefined || sql.type !== 'Literal' || typeof sql.value !== 'string') {return false;}
  return sql.value.includes('?') || /\$\d+/.test(sql.value);
}

function sinkClass(name: string | null): StoredFinding['sinkClass'] | null {
  if (name === 'query' || name === 'execute') {return 'sqli';}
  if (name === 'send' || name === 'write') {return 'xss';}
  if (name === 'exec' || name === 'execSync') {return 'cmdi';}
  if (name === 'render') {return 'ssti';}
  return null;
}
