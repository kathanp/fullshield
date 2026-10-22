import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { parseProgram, propName, stripNode, walkAst } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_MWORDER';

export interface Cover {
  route: string;
  covers: boolean;
  index: number | null;
}

interface Step {
  kind: 'use' | 'route';
  path: string;
  callsNext: boolean;
  error: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeMiddleware(source: string): { covers: Cover[] } {
  if (!enabled()) {return { covers: [] };}
  const program = parseProgram(source);
  if (program === null) {return { covers: [] };}
  const steps = stepsOf(program);
  const covers: Cover[] = [];
  steps.forEach((step, index) => {
    if (step.kind !== 'route') {return;}
    let match: number | null = null;
    for (let cursor = 0; cursor < index; cursor += 1) {
      const earlier = steps[cursor];
      if (earlier === undefined || earlier.kind !== 'use' || earlier.error || !earlier.callsNext) {continue;}
      if (!pathCovers(earlier.path, step.path)) {continue;}
      match = cursor;
      break;
    }
    covers.push({ route: step.path, covers: match !== null, index: match });
  });
  return { covers };
}

function stepsOf(program: TSESTree.Program): Step[] {
  const steps: Step[] = [];
  const locals = new Map<string, TSESTree.Node>();
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {locals.set(stmt.id.name, stmt);}
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'CallExpression') {continue;}
    const call = stmt.expression;
    const callee = stripNode(call.callee);
    if (callee.type !== 'MemberExpression') {continue;}
    const name = propName(callee);
    if (name !== 'use' && name !== 'get' && name !== 'post') {continue;}
    const path = pathArg(call);
    const handler = handlerArg(call, locals);
    if (name === 'use') {
      steps.push({ kind: 'use', path: path ?? '/', callsNext: handler !== null && callsNext(handler), error: handler !== null && handler.params.length === 4 });
    } else if (path !== null) {
      steps.push({ kind: 'route', path, callsNext: false, error: false });
    }
  }
  return steps;
}

function pathArg(call: TSESTree.CallExpression): string | null {
  const first = call.arguments[0];
  if (first !== undefined && first.type === 'Literal' && typeof first.value === 'string') {return first.value;}
  return null;
}

function handlerArg(call: TSESTree.CallExpression, locals: ReadonlyMap<string, TSESTree.Node>): TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression | null {
  const candidate = [...call.arguments].reverse().find((arg) => arg.type !== 'Literal');
  if (candidate === undefined) {return null;}
  if (candidate.type === 'ArrowFunctionExpression' || candidate.type === 'FunctionExpression') {return candidate;}
  if (candidate.type === 'CallExpression') {
    const callee = stripNode(candidate.callee);
    if (callee.type === 'Identifier') {
      const fn = locals.get(callee.name);
      if (fn !== undefined && (fn.type === 'FunctionDeclaration' || fn.type === 'FunctionExpression')) {return returnedHandler(fn);}
    }
  }
  return null;
}

function returnedHandler(fn: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression): TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression | null {
  let found: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression | null = null;
  walkAst(fn, (node) => {
    if (node.type === 'ReturnStatement' && node.argument !== null && (node.argument.type === 'ArrowFunctionExpression' || node.argument.type === 'FunctionExpression')) {
      found = node.argument;
    }
  });
  return found;
}

function callsNext(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression | TSESTree.FunctionDeclaration): boolean {
  let found = false;
  walkAst(fn, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'next') {found = true;}
  });
  return found;
}

function pathCovers(mount: string, route: string): boolean {
  if (mount === '/' || mount === '') {return true;}
  return route === mount || route.startsWith(`${mount}/`);
}
