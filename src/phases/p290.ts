import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ENVSRC';

export interface EnvFinding {
  file: string;
  line: number;
  origin: 'environment';
  severity: 'info' | 'medium';
  sinkClass: 'cmdi' | 'eval' | 'ssti';
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeEnvSources(
  source: string,
  options?: { file?: string; trustEnvironment?: boolean },
): { findings: EnvFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const severity: EnvFinding['severity'] = options?.trustEnvironment === false ? 'medium' : 'info';
  const findings: EnvFinding[] = [];
  const env = new Map<string, boolean>();
  const bag: EnvWalk = { file, severity, findings, walk: () => undefined };
  bag.walk = (stmts) => {
    for (const stmt of stmts) {walkEnv(stmt, env, bag);}
  };
  bag.walk(program.body);
  return { findings };
}

export function scanTreeForEnv(root: string): EnvFinding[] {
  if (!enabled()) {return [];}
  const findings: EnvFinding[] = [];
  const visit = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      const stat = statSync(full);
      if (stat.isDirectory()) {visit(full); continue;}
      if (!name.endsWith('.js') && !name.endsWith('.ts')) {continue;}
      findings.push(...analyzeEnvSources(readFileSync(full, 'utf8'), { file: full }).findings);
    }
  };
  visit(root);
  return findings;
}

interface EnvWalk {
  file: string;
  severity: EnvFinding['severity'];
  findings: EnvFinding[];
  walk: (stmts: readonly TSESTree.Statement[]) => void;
}

function walkEnv(stmt: TSESTree.Statement, env: Map<string, boolean>, bag: EnvWalk): void {
  if (stmt.type === 'FunctionDeclaration' || stmt.type === 'BlockStatement') {
    bag.walk(stmt.type === 'BlockStatement' ? stmt.body : stmt.body.body);
    return;
  }
  if (stmt.type === 'VariableDeclaration') {bindEnvVars(stmt, env);}
  noteEnvCall(stmt, env, bag);
  noteEnvAssign(stmt, env);
}

function bindEnvVars(stmt: TSESTree.VariableDeclaration, env: Map<string, boolean>): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type === 'Identifier' && decl.init !== null) {env.set(decl.id.name, envInit(decl.init, env));}
  }
}

function envInit(init: TSESTree.Expression, env: ReadonlyMap<string, boolean>): boolean {
  return isEnv(init) || (init.type === 'Identifier' && env.get(init.name) === true);
}

function noteEnvCall(stmt: TSESTree.Statement, env: Map<string, boolean>, bag: EnvWalk): void {
  if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {return;}
  const sink = sinkOf(stmt.expression);
  if (sink !== null && callUsesEnv(stmt.expression, env)) {
    bag.findings.push({ file: bag.file, line: lineOf(stmt.expression), origin: 'environment', severity: bag.severity, sinkClass: sink });
  }
}

function noteEnvAssign(stmt: TSESTree.Statement, env: Map<string, boolean>): void {
  if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'AssignmentExpression') {return;}
  if (stmt.expression.left.type !== 'Identifier') {return;}
  env.set(stmt.expression.left.name, isEnv(stmt.expression.right));
}

function isEnv(node: TSESTree.Node): boolean {
  const current = stripNode(node);
  if (current.type === 'MemberExpression' && current.object.type === 'MemberExpression' && current.object.object.type === 'Identifier' && current.object.object.name === 'process' && propName(current.object) === 'env') {
    return true;
  }
  if (current.type === 'BinaryExpression') {return isEnv(current.left) || isEnv(current.right);}
  if (current.type === 'TemplateLiteral') {return current.expressions.some((expr) => isEnv(expr));}
  return false;
}

function callUsesEnv(call: TSESTree.CallExpression, env: ReadonlyMap<string, boolean>): boolean {
  return call.arguments.some((arg) => arg.type !== 'SpreadElement' && (isEnv(arg) || (arg.type === 'Identifier' && env.get(arg.name) === true)));
}

function sinkOf(call: TSESTree.CallExpression): EnvFinding['sinkClass'] | null {
  const callee = stripNode(call.callee);
  const name = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' ? propName(callee) : null;
  if (name === 'exec' || name === 'execSync' || name === 'spawn') {return 'cmdi';}
  if (name === 'eval' || name === 'Function') {return 'eval';}
  if (name === 'render') {return 'ssti';}
  return null;
}
