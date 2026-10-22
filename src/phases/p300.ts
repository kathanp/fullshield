import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, walkAst, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_WS';

export interface WsFinding {
  file: string;
  line: number;
  route: string | null;
  auth: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeWs(source: string, options?: { file?: string }): { findings: WsFinding[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { findings: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const events: UnsoundEvent[] = [];
  const findings: WsFinding[] = [];
  const connectionAuth = hasConnectionAuth(program);
  walkAst(program, (node) => {
    if (node.type !== 'CallExpression') {return;}
    const callee = stripNode(node.callee);
    if (callee.type !== 'MemberExpression' || propName(callee) !== 'on') {return;}
    const eventName = node.arguments[0];
    const handler = node.arguments[1];
    if (handler === undefined || (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression')) {return;}
    const literal = eventName !== undefined && eventName.type === 'Literal' && typeof eventName.value === 'string' ? eventName.value : null;
    if (literal === null) {events.push({ kind: 'dynamic-property', file, line: lineOf(node), reason: 'computed event' });}
    const payload = handler.params[0];
    const payloadName = payload !== undefined && payload.type === 'Identifier' ? payload.name : null;
    if (payloadName !== null && reachesQuery(handler, payloadName)) {
      findings.push({ file, line: lineOf(node), route: literal === null ? null : `WS ${literal}`, auth: connectionAuth });
    }
  });
  return { findings, events };
}

function hasConnectionAuth(program: TSESTree.Program): boolean {
  let found = false;
  walkAst(program, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const name = propName(node.callee);
      if (name === 'use' || name === 'verifyClient') {found = true;}
    }
  });
  return found;
}

function reachesQuery(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression, payload: string): boolean {
  let found = false;
  walkAst(fn, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && propName(node.callee) === 'query') {
      const arg = node.arguments[0];
      if (arg !== undefined && uses(arg, payload)) {found = true;}
    }
  });
  return found;
}

function uses(node: TSESTree.Node, name: string): boolean {
  if (node.type === 'Identifier') {return node.name === name;}
  if (node.type === 'MemberExpression') {return uses(node.object, name);}
  if (node.type === 'BinaryExpression') {return uses(node.left, name) || uses(node.right, name);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => uses(expr, name));}
  return false;
}
