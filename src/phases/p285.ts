import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_NARROW';

export interface NarrowFinding {
  file: string;
  line: number;
  labels: string[];
}

interface Refine {
  dropStrings: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeNarrowing(source: string, options?: { file?: string }): { findings: NarrowFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const findings: NarrowFinding[] = [];
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration') {execBlock(stmt.body.body, new Map(), findings, file);}
  }
  return { findings };
}

function execBlock(
  stmts: readonly TSESTree.Statement[],
  env: Map<string, Refine>,
  findings: NarrowFinding[],
  file: string,
): Map<string, Refine> {
  let current = env;
  for (const stmt of stmts) {current = exec(stmt, current, findings, file);}
  return current;
}

function exec(
  stmt: TSESTree.Statement,
  env: Map<string, Refine>,
  findings: NarrowFinding[],
  file: string,
): Map<string, Refine> {
  if (stmt.type === 'BlockStatement') {return execBlock(stmt.body, new Map(env), findings, file);}
  if (stmt.type === 'VariableDeclaration') {return execVars(stmt, env);}
  if (stmt.type === 'ExpressionStatement') {return execExpr(stmt, env, findings, file);}
  if (stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement') {return env;}
  if (stmt.type === 'IfStatement') {return execIf(stmt, env, findings, file);}
  if (stmt.type === 'SwitchStatement' && stmt.discriminant.type === 'Identifier') {return execSwitch(stmt, env, findings, file);}
  return env;
}

function execVars(stmt: TSESTree.VariableDeclaration, env: Map<string, Refine>): Map<string, Refine> {
  const next = new Map(env);
  for (const decl of stmt.declarations) {
    if (decl.id.type === 'Identifier' && decl.init !== null) {next.set(decl.id.name, refineOfExpr(decl.init));}
  }
  return next;
}

function execExpr(
  stmt: TSESTree.ExpressionStatement,
  env: Map<string, Refine>,
  findings: NarrowFinding[],
  file: string,
): Map<string, Refine> {
  const expr = stripNode(stmt.expression);
  if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
    const next = new Map(env);
    next.set(expr.left.name, refineOfExpr(expr.right));
    return next;
  }
  if (expr.type === 'CallExpression') {noteSink(expr, env, findings, file);}
  return env;
}

function execSwitch(
  stmt: TSESTree.SwitchStatement,
  env: Map<string, Refine>,
  findings: NarrowFinding[],
  file: string,
): Map<string, Refine> {
  if (stmt.discriminant.type !== 'Identifier') {return env;}
  for (const item of stmt.cases) {execCase(item, stmt.discriminant.name, env, findings, file);}
  return env;
}

function execCase(
  item: TSESTree.SwitchCase,
  name: string,
  env: Map<string, Refine>,
  findings: NarrowFinding[],
  file: string,
): void {
  const next = new Map(env);
  if (item.test !== null && item.test.type === 'Literal') {next.set(name, { dropStrings: true });}
  execBlock(item.consequent, next, findings, file);
}

function execIf(
  stmt: TSESTree.IfStatement,
  env: Map<string, Refine>,
  findings: NarrowFinding[],
  file: string,
): Map<string, Refine> {
  const ref = condition(stmt.test);
  if (ref !== null && !ref.positive && aborts(stmt.consequent)) {
    const next = new Map(env);
    next.set(ref.name, { dropStrings: true });
    return next;
  }
  const thenEnv = new Map(env);
  if (ref !== null && ref.positive) {thenEnv.set(ref.name, { dropStrings: true });}
  const left = exec(stmt.consequent, thenEnv, findings, file);
  if (stmt.alternate === null) {return aborts(stmt.consequent) ? left : env;}
  const right = exec(stmt.alternate, new Map(env), findings, file);
  return intersect(left, right);
}

function noteSink(call: TSESTree.CallExpression, env: ReadonlyMap<string, Refine>, findings: NarrowFinding[], file: string): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || propName(callee) !== 'query') {return;}
  const arg = call.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') {return;}
  if (!exprTainted(arg, env)) {return;}
  if (exprDropped(arg, env)) {return;}
  findings.push({ file, line: lineOf(call), labels: ['sqli'] });
}

function condition(node: TSESTree.Node): { name: string; positive: boolean } | null {
  const current = stripNode(node);
  const negated = negatedCondition(current);
  if (negated !== undefined) {return negated;}
  return typeofNumber(current)
    ?? typeofOther(current)
    ?? instanceofDate(current)
    ?? booleanCompare(current)
    ?? callPredicate(current);
}

function negatedCondition(current: TSESTree.Node): { name: string; positive: boolean } | null | undefined {
  if (current.type !== 'UnaryExpression' || current.operator !== '!') {return undefined;}
  const inner = condition(current.argument);
  if (inner === null) {return null;}
  return { name: inner.name, positive: !inner.positive };
}

function typeofNumber(current: TSESTree.Node): { name: string; positive: boolean } | null {
  if (!isTypeofCompare(current, '===') && !isTypeofCompare(current, '==')) {return null;}
  if (current.right.value !== 'number') {return null;}
  return { name: current.left.argument.name, positive: true };
}

function typeofOther(current: TSESTree.Node): { name: string; positive: boolean } | null {
  if (!isTypeofCompare(current, '!==')) {return null;}
  if (current.right.value !== 'number' && current.right.value !== 'boolean') {return null;}
  return { name: current.left.argument.name, positive: false };
}

function isTypeofCompare(current: TSESTree.Node, operator: string): current is TSESTree.BinaryExpression & {
  left: TSESTree.UnaryExpression & { argument: TSESTree.Identifier };
  right: TSESTree.Literal;
} {
  return current.type === 'BinaryExpression'
    && current.operator === operator
    && current.left.type === 'UnaryExpression'
    && current.left.operator === 'typeof'
    && current.left.argument.type === 'Identifier'
    && current.right.type === 'Literal';
}

function instanceofDate(current: TSESTree.Node): { name: string; positive: boolean } | null {
  if (current.type !== 'BinaryExpression' || current.operator !== 'instanceof') {return null;}
  if (current.left.type !== 'Identifier' || current.right.type !== 'Identifier' || current.right.name !== 'Date') {return null;}
  return { name: current.left.name, positive: true };
}

function booleanCompare(current: TSESTree.Node): { name: string; positive: boolean } | null {
  if (current.type !== 'BinaryExpression' || current.left.type !== 'Identifier') {return null;}
  if (current.right.type !== 'Literal' || typeof current.right.value !== 'boolean') {return null;}
  if (current.operator !== '===' && current.operator !== '==' && current.operator !== '!==') {return null;}
  return { name: current.left.name, positive: current.operator !== '!==' };
}

function callPredicate(current: TSESTree.Node): { name: string; positive: boolean } | null {
  const named = namedCall(current);
  if (named === null) {return null;}
  if (named.method === 'isInteger' || named.method === 'isArray') {return { name: named.arg, positive: true };}
  if (named.method === 'test' && digitRegex(named.object)) {return { name: named.arg, positive: true };}
  return null;
}

function namedCall(current: TSESTree.Node): { method: string; arg: string; object: TSESTree.Node } | null {
  if (current.type !== 'CallExpression' || current.callee.type !== 'MemberExpression') {return null;}
  const method = propName(current.callee);
  const arg = current.arguments[0];
  if (method === null || arg === undefined || arg.type !== 'Identifier') {return null;}
  return { method, arg: arg.name, object: current.callee.object };
}

function digitRegex(object: TSESTree.Node): boolean {
  return object.type === 'Literal' && 'regex' in object && object.regex?.pattern === '^\\d+$';
}

function refineOfExpr(node: TSESTree.Node): Refine {
  if (isRequestSource(node)) {return { dropStrings: false };}
  if (node.type === 'Literal' && (typeof node.value === 'number' || typeof node.value === 'boolean')) {return { dropStrings: true };}
  if (node.type === 'Identifier') {return { dropStrings: false };}
  return { dropStrings: false };
}

function exprTainted(node: TSESTree.Node, env: ReadonlyMap<string, Refine>): boolean {
  if (isRequestSource(node)) {return true;}
  if (node.type === 'Identifier') {return env.has(node.name);}
  if (node.type === 'BinaryExpression') {return exprTainted(node.left, env) || exprTainted(node.right, env);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => exprTainted(expr, env));}
  return false;
}

function exprDropped(node: TSESTree.Node, env: ReadonlyMap<string, Refine>): boolean {
  if (node.type === 'Identifier') {return env.get(node.name)?.dropStrings === true;}
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const leftLit = node.left.type === 'Literal';
    const rightLit = node.right.type === 'Literal';
    if (leftLit && node.right.type !== 'Literal') {return exprDropped(node.right, env);}
    if (rightLit && node.left.type !== 'Literal') {return exprDropped(node.left, env);}
  }
  if (node.type === 'TemplateLiteral') {return node.expressions.every((expr) => exprDropped(expr, env));}
  return false;
}

function aborts(stmt: TSESTree.Statement): boolean {
  if (stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement') {return true;}
  if (stmt.type === 'BlockStatement') {return stmt.body.some((inner) => aborts(inner));}
  return false;
}

function intersect(left: ReadonlyMap<string, Refine>, right: ReadonlyMap<string, Refine>): Map<string, Refine> {
  const out = new Map<string, Refine>();
  for (const name of new Set([...left.keys(), ...right.keys()])) {
    out.set(name, { dropStrings: left.get(name)?.dropStrings === true && right.get(name)?.dropStrings === true });
  }
  return out;
}
