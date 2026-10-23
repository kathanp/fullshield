import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, walkAst } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_KOAHONO';

export interface FrameworkFinding {
  file: string;
  line: number;
  framework: 'koa' | 'hono';
  finding: boolean;
}

export interface Cover {
  covers: boolean;
  dominates: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeKoaHono(source: string, options?: { file?: string }): { findings: FrameworkFinding[]; covers: Cover[] } {
  if (!enabled()) {return { findings: [], covers: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], covers: [] };}
  const file = options?.file ?? 'inline.js';
  if (usesHono(program)) {return analyzeHono(program, file);}
  return analyzeKoa(program, file);
}

function usesHono(program: TSESTree.Program): boolean {
  let found = false;
  walkAst(program, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const object = node.callee.object;
      if (object.type === 'Identifier' && object.name === 'c') {found = true;}
      if (propName(node.callee) === 'query' && object.type === 'MemberExpression') {found = true;}
    }
    if (node.type === 'Identifier' && node.name === 'Hono') {found = true;}
  });
  return found;
}

function analyzeKoa(program: TSESTree.Program, file: string): { findings: FrameworkFinding[]; covers: Cover[] } {
  const uses: { fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression; awaits: boolean; dominates: boolean }[] = [];
  for (const stmt of program.body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    const callee = stripNode(stmt.expression.callee);
    if (callee.type !== 'MemberExpression' || propName(callee) !== 'use') {continue;}
    const handler = stmt.expression.arguments[0];
    if (handler === undefined || (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression')) {continue;}
    uses.push({ fn: handler, awaits: awaitsNext(handler), dominates: dominatesBeforeNext(handler) });
  }
  const downstream = uses.length > 1;
  const guard = uses[0];
  const covers: Cover[] = guard === undefined ? [] : [{ covers: downstream && guard.awaits, dominates: downstream && guard.dominates }];
  const findings: FrameworkFinding[] = [];
  for (const item of uses) {
    const sink = sinkLine(item.fn);
    if (sink !== null) {findings.push({ file, line: sink, framework: 'koa', finding: true });}
  }
  return { findings, covers };
}

function analyzeHono(program: TSESTree.Program, file: string): { findings: FrameworkFinding[]; covers: Cover[] } {
  const findings: FrameworkFinding[] = [];
  walkAst(program, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return;}
    const method = propName(node.callee);
    if (method !== 'get' && method !== 'post') {return;}
    const handler = [...node.arguments].reverse().find((arg) => arg.type === 'ArrowFunctionExpression' || arg.type === 'FunctionExpression');
    if (handler === undefined || (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression')) {return;}
    const cleared = node.arguments.some((arg) => arg.type === 'CallExpression' && validatorClears(arg));
    if (cleared) {return;}
    const sink = sinkLine(handler);
    if (sink !== null) {findings.push({ file, line: sink, framework: 'hono', finding: true });}
  });
  return { findings, covers: [] };
}

function awaitsNext(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression): boolean {
  let found = false;
  walkAst(fn, (node) => {
    if (node.type === 'AwaitExpression' && node.argument.type === 'CallExpression' && node.argument.callee.type === 'Identifier' && node.argument.callee.name === 'next') {found = true;}
  });
  return found;
}

function dominatesBeforeNext(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression): boolean {
  if (fn.body.type !== 'BlockStatement') {return false;}
  let sawNext = false;
  for (const stmt of fn.body.body) {
    if (!sawNext && assignsUser(stmt)) {return true;}
    if (statementAwaits(stmt)) {sawNext = true;}
  }
  return false;
}

function statementAwaits(stmt: TSESTree.Statement): boolean {
  let found = false;
  walkAst(stmt, (node) => {
    if (node.type === 'AwaitExpression' && node.argument.type === 'CallExpression' && node.argument.callee.type === 'Identifier' && node.argument.callee.name === 'next') {found = true;}
  });
  return found;
}

function assignsUser(stmt: TSESTree.Statement): boolean {
  let found = false;
  walkAst(stmt, (node) => {
    if (node.type === 'AssignmentExpression' && node.left.type === 'MemberExpression' && node.left.property.type === 'Identifier' && node.left.property.name === 'user') {found = true;}
  });
  return found;
}

function sinkLine(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression): number | null {
  let line: number | null = null;
  walkAst(fn, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && propName(node.callee) === 'query') {line = lineOf(node);}
  });
  return line;
}

function validatorClears(call: TSESTree.CallExpression): boolean {
  const callee = stripNode(call.callee);
  const name = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' ? propName(callee) : null;
  if (name !== 'zValidator' && name !== 'validator') {return false;}
  return call.arguments.some((arg) => arg.type !== 'SpreadElement' && clears(arg));
}

function clears(node: TSESTree.Node): boolean {
  if (node.type === 'CallExpression') {
    const callee = stripNode(node.callee);
    if (callee.type === 'MemberExpression' && propName(callee) === 'number') {return true;}
    return node.arguments.some((arg) => arg.type !== 'SpreadElement' && clears(arg));
  }
  if (node.type === 'ObjectExpression') {
    return node.properties.some((prop) => {
      if (prop.type !== 'Property') {return false;}
      if (prop.key.type === 'Identifier' && prop.key.name === 'type' && prop.value.type === 'Literal' && prop.value.value === 'number') {return true;}
      return clears(prop.value);
    });
  }
  return false;
}
