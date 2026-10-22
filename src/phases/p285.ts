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
  if (stmt.type === 'VariableDeclaration') {
    const next = new Map(env);
    for (const decl of stmt.declarations) {
      if (decl.id.type === 'Identifier' && decl.init !== null) {next.set(decl.id.name, refineOfExpr(decl.init));}
    }
    return next;
  }
  if (stmt.type === 'ExpressionStatement') {
    const expr = stripNode(stmt.expression);
    if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
      const next = new Map(env);
      next.set(expr.left.name, refineOfExpr(expr.right));
      return next;
    }
    if (expr.type === 'CallExpression') {noteSink(expr, env, findings, file);}
    return env;
  }
  if (stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement') {return env;}
  if (stmt.type === 'IfStatement') {return execIf(stmt, env, findings, file);}
  if (stmt.type === 'SwitchStatement' && stmt.discriminant.type === 'Identifier') {
    for (const item of stmt.cases) {
      const next = new Map(env);
      if (item.test !== null && item.test.type === 'Literal') {next.set(stmt.discriminant.name, { dropStrings: true });}
      execBlock(item.consequent, next, findings, file);
    }
    return env;
  }
  return env;
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
  if (current.type === 'UnaryExpression' && current.operator === '!') {
    const inner = condition(current.argument);
    if (inner === null) {return null;}
    return { name: inner.name, positive: !inner.positive };
  }
  if (current.type === 'BinaryExpression' && (current.operator === '===' || current.operator === '==') && current.left.type === 'UnaryExpression' && current.left.operator === 'typeof' && current.left.argument.type === 'Identifier' && current.right.type === 'Literal' && current.right.value === 'number') {
    return { name: current.left.argument.name, positive: true };
  }
  if (current.type === 'BinaryExpression' && current.operator === '!==' && current.left.type === 'UnaryExpression' && current.left.operator === 'typeof' && current.left.argument.type === 'Identifier' && current.right.type === 'Literal' && (current.right.value === 'number' || current.right.value === 'boolean')) {
    return { name: current.left.argument.name, positive: false };
  }
  if (current.type === 'BinaryExpression' && current.operator === 'instanceof' && current.left.type === 'Identifier' && current.right.type === 'Identifier' && current.right.name === 'Date') {
    return { name: current.left.name, positive: true };
  }
  if (current.type === 'BinaryExpression' && (current.operator === '===' || current.operator === '==' || current.operator === '!==') && current.left.type === 'Identifier' && current.right.type === 'Literal' && typeof current.right.value === 'boolean') {
    return { name: current.left.name, positive: current.operator !== '!==' };
  }
  if (current.type === 'CallExpression' && current.callee.type === 'MemberExpression' && propName(current.callee) === 'isInteger' && current.arguments[0]?.type === 'Identifier') {
    const arg = current.arguments[0];
    return arg.type === 'Identifier' ? { name: arg.name, positive: true } : null;
  }
  if (current.type === 'CallExpression' && current.callee.type === 'MemberExpression' && propName(current.callee) === 'isArray' && current.arguments[0]?.type === 'Identifier') {
    const arg = current.arguments[0];
    return arg.type === 'Identifier' ? { name: arg.name, positive: true } : null;
  }
  if (current.type === 'CallExpression' && current.callee.type === 'MemberExpression' && propName(current.callee) === 'test' && current.arguments[0]?.type === 'Identifier') {
    const arg = current.arguments[0];
    if (arg.type !== 'Identifier') {return null;}
    const regex = current.callee.type === 'MemberExpression' ? current.callee.object : null;
    if (regex !== null && regex.type === 'Literal' && 'regex' in regex && regex.regex?.pattern === '^\\d+$') {return { name: arg.name, positive: true };}
  }
  return null;
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
