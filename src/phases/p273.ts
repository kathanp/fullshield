import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  isAstNode,
  isRequestSource,
  lineOf,
  parseProgram,
  propName,
  stripNode,
  walkAst,
  type UnsoundEvent,
} from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CGPT';

export interface CallEdge {
  line: number;
  target: string;
}

export interface CallGraphResult {
  edges: CallEdge[];
  events: UnsoundEvent[];
  findings: { file: string; line: number; target: string }[];
}

export interface EdgeDiff {
  gained: string[];
  lost: string[];
}

interface Table {
  keys: Map<string, TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression>;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function diffCallEdges(before: readonly string[], after: readonly string[]): EdgeDiff {
  const prev = new Set(before);
  const next = new Set(after);
  return {
    gained: [...next].filter((edge) => !prev.has(edge)).sort(),
    lost: [...prev].filter((edge) => !next.has(edge)).sort(),
  };
}

export function analyzeCallGraph(source: string, options?: { file?: string }): CallGraphResult {
  if (!enabled()) {return { edges: [], events: [], findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { edges: [], events: [], findings: [] };}
  const file = options?.file ?? 'inline.js';
  const tables = new Map<string, Table>();
  const functions = new Map<string, TSESTree.FunctionDeclaration>();
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {functions.set(stmt.id.name, stmt);}
    if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) {
        if (decl.id.type !== 'Identifier' || decl.init === null || decl.init.type !== 'ObjectExpression') {continue;}
        const table: Table = { keys: new Map() };
        for (const prop of decl.init.properties) {
          if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {continue;}
          if (prop.value.type === 'FunctionExpression' || prop.value.type === 'ArrowFunctionExpression') {
            table.keys.set(prop.key.name, prop.value);
          }
        }
        if (table.keys.size > 0) {tables.set(decl.id.name, table);}
      }
    }
  }
  const edges: CallEdge[] = [];
  const events: UnsoundEvent[] = [];
  const findings: { file: string; line: number; target: string }[] = [];
  const visitCalls = (node: TSESTree.Node, owner: string | null): void => {
    if (node.type === 'CallExpression') {noteCall(node, owner, program, tables, functions, file, edges, events, findings);}
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range' || key === 'parent') {continue;}
      const child: unknown = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (isAstNode(item)) {visitCalls(item, owner);}
        }
      } else if (isAstNode(child)) {
        visitCalls(child, owner);
      }
    }
  };
  for (const [name, fn] of functions) {visitCalls(fn.body, name);}
  for (const stmt of program.body) {
    if (stmt.type !== 'FunctionDeclaration') {visitCalls(stmt, null);}
  }
  return { edges, events, findings };
}

function noteCall(
  call: TSESTree.CallExpression,
  owner: string | null,
  program: TSESTree.Program,
  tables: ReadonlyMap<string, Table>,
  functions: ReadonlyMap<string, TSESTree.FunctionDeclaration>,
  file: string,
  edges: CallEdge[],
  events: UnsoundEvent[],
  findings: CallGraphResult['findings'],
): void {
  const callee = stripNode(call.callee);
  if (callee.type === 'MemberExpression') {
    const object = stripNode(callee.object);
    if (object.type !== 'Identifier') {return;}
    const table = tables.get(object.name);
    if (table === undefined) {return;}
    const resolved = resolveKey(callee, owner, program, functions, table);
    if (resolved.dynamic) {
      events.push({ kind: 'dynamic-property', file, line: lineOf(call), reason: 'computed handler key' });
    }
    if (resolved.unresolved) {
      events.push({ kind: 'unknown-callee', file, line: lineOf(call), reason: 'unknown callee' });
    }
    for (const target of resolved.targets) {
      edges.push({ line: lineOf(call), target });
      const fn = table.keys.get(target);
      if (fn !== undefined && functionSinksRequest(fn)) {
        findings.push({ file, line: lineOf(call), target });
      }
    }
    return;
  }
  if (callee.type === 'Identifier' && !functions.has(callee.name) && !tables.has(callee.name)) {
    const known = new Set(['require', 'db']);
    if (!known.has(callee.name)) {
      events.push({ kind: 'unknown-callee', file, line: lineOf(call), reason: 'unknown callee' });
    }
  }
}

function resolveKey(
  member: TSESTree.MemberExpression,
  owner: string | null,
  program: TSESTree.Program,
  functions: ReadonlyMap<string, TSESTree.FunctionDeclaration>,
  table: Table,
): { targets: string[]; dynamic: boolean; unresolved: boolean } {
  const all = [...table.keys.keys()].sort();
  if (!member.computed) {
    const name = propName(member);
    return name !== null && table.keys.has(name)
      ? { targets: [name], dynamic: false, unresolved: false }
      : { targets: [], dynamic: false, unresolved: true };
  }
  const key = stripNode(member.property);
  if (key.type === 'Literal' && typeof key.value === 'string' && table.keys.has(key.value)) {
    return { targets: [key.value], dynamic: false, unresolved: false };
  }
  if (isRequestSource(key)) {return { targets: all, dynamic: true, unresolved: false };}
  if (key.type === 'Identifier' && owner !== null) {
    const fn = functions.get(owner);
    if (fn !== undefined) {
      const index = fn.params.findIndex((param) => param.type === 'Identifier' && param.name === key.name);
      if (index >= 0) {
        const literals = new Set<string>();
        let dynamic = false;
        walkAst(program, (node) => {
          if (node.type !== 'CallExpression') {return;}
          const callee = stripNode(node.callee);
          if (callee.type !== 'Identifier' || callee.name !== owner) {return;}
          const arg = node.arguments[index];
          if (arg === undefined || arg.type === 'SpreadElement') {return;}
          if (isRequestSource(arg)) {dynamic = true; return;}
          if (arg.type === 'Literal' && typeof arg.value === 'string') {literals.add(arg.value);}
        });
        if (dynamic) {return { targets: all, dynamic: true, unresolved: false };}
        const targets = [...literals].filter((name) => table.keys.has(name)).sort();
        if (targets.length > 0) {return { targets, dynamic: false, unresolved: false };}
      }
    }
  }
  return { targets: [], dynamic: false, unresolved: true };
}

function functionSinksRequest(fn: TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): boolean {
  let hit = false;
  walkAst(fn.body, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && propName(node.callee) === 'query') {
      hit = node.arguments.some((arg) => arg.type !== 'SpreadElement' && touchesRequest(arg));
    }
  });
  return hit;
}

function touchesRequest(node: TSESTree.Node): boolean {
  if (isRequestSource(node)) {return true;}
  if (node.type === 'BinaryExpression') {return touchesRequest(node.left) || touchesRequest(node.right);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => touchesRequest(expr));}
  return false;
}
