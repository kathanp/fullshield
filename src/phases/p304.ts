import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, walkAst, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ELECTRONIPC';

export interface IpcFinding {
  file: string;
  line: number;
  route: string;
  origin: 'renderer';
  confidence: 'high' | 'low';
  witness: string;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeIpc(source: string, facts: { sandbox: boolean; nodeIntegration: boolean }, options?: { file?: string }): { findings: IpcFinding[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { findings: [], events: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events: [] };}
  const file = options?.file ?? 'inline.js';
  const events: UnsoundEvent[] = [];
  const bridge = bridgeChannels(program, events, file);
  const findings: IpcFinding[] = [];
  walkAst(program, (node) => {noteIpc(node, bridge, facts, file, findings);});
  return { findings, events };
}

function noteIpc(
  node: TSESTree.Node,
  bridge: ReadonlySet<string>,
  facts: { sandbox: boolean; nodeIntegration: boolean },
  file: string,
  findings: IpcFinding[],
): void {
  const ipc = ipcHandler(node);
  if (ipc === null || guarded(ipc.handler) || !usesArg(ipc.handler)) {return;}
  const exposed = bridge.has(ipc.channel);
  findings.push({
    file,
    line: lineOf(node),
    route: `IPC ${ipc.channel}`,
    origin: 'renderer',
    confidence: exposed || facts.nodeIntegration ? 'high' : 'low',
    witness: exposed ? 'bridge' : 'no bridge entry',
  });
}

function ipcHandler(node: TSESTree.Node): { channel: string; handler: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression } | null {
  if (node.type !== 'CallExpression') {return null;}
  const callee = stripNode(node.callee);
  if (callee.type !== 'MemberExpression') {return null;}
  const name = propName(callee);
  if (name !== 'handle' && name !== 'on') {return null;}
  const channelNode = node.arguments[0];
  const handler = node.arguments[1];
  if (channelNode === undefined || channelNode.type !== 'Literal' || typeof channelNode.value !== 'string') {return null;}
  if (handler === undefined || (handler.type !== 'ArrowFunctionExpression' && handler.type !== 'FunctionExpression')) {return null;}
  return { channel: channelNode.value, handler };
}

function bridgeChannels(program: TSESTree.Program, events: UnsoundEvent[], file: string): Set<string> {
  const names = new Set<string>();
  walkAst(program, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression' || propName(node.callee) !== 'exposeInMainWorld') {return;}
    const api = node.arguments[1];
    if (api === undefined || api.type !== 'ObjectExpression') {
      events.push({ kind: 'dynamic-property', file, line: lineOf(node), reason: 'computed expose' });
      return;
    }
    for (const prop of api.properties) {
      if (prop.type === 'Property' && prop.key.type === 'Identifier') {names.add(prop.key.name);}
      if (prop.type === 'Property' && prop.computed) {events.push({ kind: 'dynamic-property', file, line: lineOf(prop), reason: 'computed expose' });}
    }
  });
  return names;
}

function guarded(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression): boolean {
  let safe = false;
  walkAst(fn, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && propName(node.callee) === 'basename') {safe = true;}
  });
  return safe;
}

function usesArg(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression): boolean {
  const names = fn.params.flatMap((param, index) => param.type === 'Identifier' && index > 0 ? [param.name] : []);
  if (names.length === 0) {return false;}
  let found = false;
  walkAst(fn, (node) => {
    if (node.type === 'CallExpression') {
      const callee = stripNode(node.callee);
      const name = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' ? propName(callee) : null;
      if (name === 'readFile' || name === 'readFileSync' || name === 'exec' || name === 'execSync' || name === 'open') {
        if (node.arguments.some((arg) => arg.type !== 'SpreadElement' && names.some((param) => uses(arg, param)))) {found = true;}
      }
    }
  });
  return found;
}

function uses(node: TSESTree.Node, name: string): boolean {
  if (node.type === 'Identifier') {return node.name === name;}
  if (node.type === 'MemberExpression') {return uses(node.object, name);}
  if (node.type === 'CallExpression') {return node.arguments.some((arg) => arg.type !== 'SpreadElement' && uses(arg, name));}
  return false;
}
