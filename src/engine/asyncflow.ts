import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

/** Phase 254. Await, events, streams, and timers. Unresolved emitters do not cross. */
export const ASYNC_FLAG = 'FULLSHIELD_EXPERIMENTAL_ASYNCFLOW';

export function asyncEnabled(): boolean {
  return process.env[ASYNC_FLAG] === '1';
}

export interface AsyncFinding {
  kind: string;
  line: number;
}

interface Listener {
  emitter: string;
  event: string;
  param: string;
  body: TSESTree.Node;
}

function isRequest(node: TSESTree.Node): boolean {
  let current: TSESTree.Node = node;
  while (current.type === 'MemberExpression') {current = current.object;}
  return current.type === 'Identifier' && current.name === 'req';
}

function exprTainted(node: TSESTree.Node, tainted: ReadonlySet<string>): boolean {
  if (isRequest(node)) {return true;}
  if (node.type === 'Identifier') {return tainted.has(node.name);}
  if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
    return exprTainted(node.left, tainted) || exprTainted(node.right, tainted);
  }
  if (node.type === 'CallExpression') {
    return node.arguments.some((arg) => arg.type !== 'SpreadElement' && exprTainted(arg, tainted));
  }
  if (node.type === 'AwaitExpression') {return exprTainted(node.argument, tainted);}
  return false;
}

function literalName(node: TSESTree.Node): string | undefined {
  if (node.type === 'Literal' && typeof node.value === 'string') {return node.value;}
  return undefined;
}

function isAstNode(value: unknown): value is TSESTree.Node {
  return value !== null && typeof value === 'object' && 'type' in value;
}

function walkAst(node: TSESTree.Node, visit: (node: TSESTree.Node) => void): void {
  for (const key of Object.keys(node)) {
    if (key === 'parent') {continue;}
    const value = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isAstNode(item)) {visit(item);}
      }
    } else if (isAstNode(value)) {
      visit(value);
    }
  }
}

function eachNode(root: TSESTree.Node, visit: (node: TSESTree.Node) => void): void {
  visit(root);
  walkAst(root, (node) => { eachNode(node, visit); });
}

function listenerOf(node: TSESTree.Node): Listener | undefined {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return undefined;}
  if (node.callee.property.type !== 'Identifier' || node.callee.property.name !== 'on') {return undefined;}
  if (node.callee.object.type !== 'Identifier') {return undefined;}
  const eventNode = node.arguments[0];
  const callback = node.arguments[1];
  if (eventNode === undefined || callback === undefined || eventNode.type === 'SpreadElement' || callback.type !== 'ArrowFunctionExpression') {
    return undefined;
  }
  const event = literalName(eventNode);
  const param = callback.params[0];
  if (event === undefined || param?.type !== 'Identifier') {return undefined;}
  return { emitter: node.callee.object.name, event, param: param.name, body: callback.body };
}

function collectListeners(program: TSESTree.Node): Listener[] {
  const listeners: Listener[] = [];
  eachNode(program, (node) => {
    const listener = listenerOf(node);
    if (listener !== undefined) {listeners.push(listener);}
  });
  return listeners;
}

interface AsyncWalk {
  listeners: readonly Listener[];
  findings: AsyncFinding[];
}

function recordTaint(node: TSESTree.Node, names: Set<string>): void {
  if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init !== null && exprTainted(node.init, names)) {
    names.add(node.id.name);
  }
}

function walkAsync(node: TSESTree.Node, names: Set<string>, state: AsyncWalk): void {
  recordTaint(node, names);
  if (node.type === 'CallExpression') {walkCall(node, names, state);}
  walkAst(node, (child) => { walkAsync(child, names, state); });
}

function walkCall(node: TSESTree.CallExpression, names: Set<string>, state: AsyncWalk): void {
  walkEmit(node, names, state);
  walkPipeline(node, names, state);
  walkThen(node, names, state);
  noteSink(node, names, state.findings);
}

function eventLiteral(node: TSESTree.CallExpressionArgument | undefined): string | undefined {
  if (node === undefined || node.type === 'SpreadElement') {return undefined;}
  return literalName(node);
}

function walkEmit(node: TSESTree.CallExpression, names: Set<string>, state: AsyncWalk): void {
  const callee = node.callee;
  if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier' || callee.property.name !== 'emit' || callee.object.type !== 'Identifier') {
    return;
  }
  const event = eventLiteral(node.arguments[0]);
  const payload = node.arguments[1];
  if (event === undefined || payload === undefined || payload.type === 'SpreadElement' || !exprTainted(payload, names)) {return;}
  for (const listener of state.listeners) {
    if (listener.emitter !== callee.object.name || listener.event !== event) {continue;}
    const inner = new Set(names);
    inner.add(listener.param);
    walkAsync(listener.body, inner, state);
  }
}

function arrowParam(node: TSESTree.CallExpressionArgument | undefined): string | undefined {
  if (node?.type !== 'ArrowFunctionExpression') {return undefined;}
  const param = node.params[0];
  if (param?.type !== 'Identifier') {return undefined;}
  return param.name;
}

function walkPipeline(node: TSESTree.CallExpression, names: Set<string>, state: AsyncWalk): void {
  const callee = node.callee;
  if (callee.type !== 'Identifier' || callee.name !== 'pipeline') {return;}
  const sourceArg = node.arguments[0];
  if (sourceArg === undefined || sourceArg.type === 'SpreadElement' || !exprTainted(sourceArg, names)) {return;}
  const param = arrowParam(node.arguments[1]);
  if (param === undefined || node.arguments[1]?.type !== 'ArrowFunctionExpression') {return;}
  const inner = new Set(names);
  inner.add(param);
  walkAsync(node.arguments[1].body, inner, state);
}

function walkThen(node: TSESTree.CallExpression, names: Set<string>, state: AsyncWalk): void {
  const callee = node.callee;
  if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier' || callee.property.name !== 'then' || !exprTainted(callee.object, names)) {
    return;
  }
  const param = arrowParam(node.arguments[0]);
  if (param === undefined || node.arguments[0]?.type !== 'ArrowFunctionExpression') {return;}
  const inner = new Set(names);
  inner.add(param);
  walkAsync(node.arguments[0].body, inner, state);
}

function taintedArg(arg: TSESTree.CallExpressionArgument, names: ReadonlySet<string>): boolean {
  return arg.type !== 'SpreadElement' && exprTainted(arg, names);
}

function noteSink(node: TSESTree.CallExpression, names: ReadonlySet<string>, findings: AsyncFinding[]): void {
  if (node.callee.type !== 'MemberExpression' || node.callee.property.type !== 'Identifier') {return;}
  if (!['query', 'exec', 'eval'].includes(node.callee.property.name)) {return;}
  if (node.arguments.some((arg) => taintedArg(arg, names))) {
    findings.push({ kind: 'async', line: node.loc?.start.line ?? 1 });
  }
}

export function asyncFindings(source: string): AsyncFinding[] {
  if (!asyncEnabled()) {return [];}
  const program = parse(source, {
    loc: true,
    range: false,
    jsx: false,
    comment: false,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  });
  const findings: AsyncFinding[] = [];
  walkAsync(program, new Set(), { listeners: collectListeners(program), findings });
  return findings;
}
