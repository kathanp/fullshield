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

function eachNode(root: TSESTree.Node, visit: (node: TSESTree.Node) => void): void {
  visit(root);
  for (const key of Object.keys(root)) {
    if (key === 'parent') {continue;}
    const value = (root as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== null && typeof item === 'object' && 'type' in item) {eachNode(item as TSESTree.Node, visit);}
      }
    } else if (value !== null && typeof value === 'object' && 'type' in value) {
      eachNode(value as TSESTree.Node, visit);
    }
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
  const listeners: Listener[] = [];
  eachNode(program, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return;}
    if (node.callee.property.type !== 'Identifier' || node.callee.property.name !== 'on') {return;}
    if (node.callee.object.type !== 'Identifier') {return;}
    const eventNode = node.arguments[0];
    const callback = node.arguments[1];
    if (eventNode === undefined || callback === undefined || eventNode.type === 'SpreadElement' || callback.type !== 'ArrowFunctionExpression') {return;}
    const event = literalName(eventNode);
    const param = callback.params[0];
    if (event === undefined || param?.type !== 'Identifier') {return;}
    listeners.push({ emitter: node.callee.object.name, event, param: param.name, body: callback.body });
  });

  const tainted = new Set<string>();
  const findings: AsyncFinding[] = [];
  const sink = (node: TSESTree.CallExpression, kind: string, names: ReadonlySet<string>): void => {
    if (node.callee.type !== 'MemberExpression' || node.callee.property.type !== 'Identifier') {return;}
    if (!['query', 'exec', 'eval'].includes(node.callee.property.name)) {return;}
    if (node.arguments.some((arg) => arg.type !== 'SpreadElement' && exprTainted(arg, names))) {
      findings.push({ kind, line: node.loc?.start.line ?? 1 });
    }
  };

  const walk = (node: TSESTree.Node, names: Set<string>): void => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init !== null && exprTainted(node.init, names)) {
      names.add(node.id.name);
    }
    if (node.type === 'CallExpression') {
      const callee = node.callee;
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && callee.property.name === 'emit' && callee.object.type === 'Identifier') {
        const eventNode = node.arguments[0];
        const payload = node.arguments[1];
        const event = eventNode === undefined || eventNode.type === 'SpreadElement' ? undefined : literalName(eventNode);
        if (event !== undefined && payload !== undefined && payload.type !== 'SpreadElement' && exprTainted(payload, names)) {
          for (const listener of listeners) {
            if (listener.emitter !== callee.object.name || listener.event !== event) {continue;}
            const inner = new Set(names);
            inner.add(listener.param);
            walk(listener.body, inner);
          }
        }
      }
      if (callee.type === 'Identifier' && callee.name === 'pipeline') {
        const sourceArg = node.arguments[0];
        const callback = node.arguments[1];
        if (sourceArg !== undefined && sourceArg.type !== 'SpreadElement' && callback?.type === 'ArrowFunctionExpression' && callback.params[0]?.type === 'Identifier' && exprTainted(sourceArg, names)) {
          const inner = new Set(names);
          inner.add(callback.params[0].name);
          walk(callback.body, inner);
        }
      }
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && callee.property.name === 'then' && exprTainted(callee.object, names)) {
        const callback = node.arguments[0];
        if (callback?.type === 'ArrowFunctionExpression' && callback.params[0]?.type === 'Identifier') {
          const inner = new Set(names);
          inner.add(callback.params[0].name);
          walk(callback.body, inner);
        }
      }
      sink(node, 'async', names);
    }
    for (const key of Object.keys(node)) {
      if (key === 'parent') {continue;}
      const value = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item !== null && typeof item === 'object' && 'type' in item) {walk(item as TSESTree.Node, names);}
        }
      } else if (value !== null && typeof value === 'object' && 'type' in value) {
        walk(value as TSESTree.Node, names);
      }
    }
  };
  walk(program, tainted);
  return findings;
}
