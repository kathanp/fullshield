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
  walkAst(program, (node) => {noteWs(node, file, findings, events, connectionAuth);});
  return { findings, events };
}

function noteWs(
  node: TSESTree.Node,
  file: string,
  findings: WsFinding[],
  events: UnsoundEvent[],
  connectionAuth: boolean,
): void {
  const handler = wsHandler(node);
  if (handler === null) {return;}
  const literal = eventLiteral(node);
  if (literal === null && node.type === 'CallExpression') {
    events.push({ kind: 'dynamic-property', file, line: lineOf(node), reason: 'computed event' });
  }
  const payloadName = payloadOf(handler);
  if (payloadName !== null && reachesQuery(handler, payloadName)) {
    findings.push({ file, line: lineOf(node), route: literal === null ? null : `WS ${literal}`, auth: connectionAuth });
  }
}

function wsHandler(node: TSESTree.Node): TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression | null {
  if (node.type !== 'CallExpression') {return null;}
  const callee = stripNode(node.callee);
  if (callee.type !== 'MemberExpression' || propName(callee) !== 'on') {return null;}
  const handler = node.arguments[1];
  if (handler === undefined || (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression')) {return null;}
  return handler;
}

function eventLiteral(node: TSESTree.Node): string | null {
  if (node.type !== 'CallExpression') {return null;}
  const eventName = node.arguments[0];
  if (eventName !== undefined && eventName.type === 'Literal' && typeof eventName.value === 'string') {return eventName.value;}
  return null;
}

function payloadOf(handler: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression): string | null {
  const payload = handler.params[0];
  if (payload !== undefined && payload.type === 'Identifier') {return payload.name;}
  return null;
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
