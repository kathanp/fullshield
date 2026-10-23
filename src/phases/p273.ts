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

interface CallBag {
  program: TSESTree.Program;
  tables: ReadonlyMap<string, Table>;
  functions: ReadonlyMap<string, TSESTree.FunctionDeclaration>;
  file: string;
  edges: CallEdge[];
  events: UnsoundEvent[];
  findings: CallGraphResult['findings'];
}

export function analyzeCallGraph(source: string, options?: { file?: string }): CallGraphResult {
  if (!enabled()) {return { edges: [], events: [], findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { edges: [], events: [], findings: [] };}
  const file = options?.file ?? 'inline.js';
  const indexed = indexProgram(program);
  const bag: CallBag = { program, tables: indexed.tables, functions: indexed.functions, file, edges: [], events: [], findings: [] };
  visitProgram(bag);
  return { edges: bag.edges, events: bag.events, findings: bag.findings };
}

function indexProgram(program: TSESTree.Program): { tables: Map<string, Table>; functions: Map<string, TSESTree.FunctionDeclaration> } {
  const tables = new Map<string, Table>();
  const functions = new Map<string, TSESTree.FunctionDeclaration>();
  for (const stmt of program.body) {indexStmt(stmt, tables, functions);}
  return { tables, functions };
}

function indexStmt(
  stmt: TSESTree.Statement,
  tables: Map<string, Table>,
  functions: Map<string, TSESTree.FunctionDeclaration>,
): void {
  if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {functions.set(stmt.id.name, stmt);}
  if (stmt.type !== 'VariableDeclaration') {return;}
  for (const decl of stmt.declarations) {indexTableDecl(decl, tables);}
}

function indexTableDecl(decl: TSESTree.VariableDeclarator, tables: Map<string, Table>): void {
  if (decl.id.type !== 'Identifier' || decl.init === null || decl.init.type !== 'ObjectExpression') {return;}
  const table = tableFromObject(decl.init);
  if (table.keys.size > 0) {tables.set(decl.id.name, table);}
}

function tableFromObject(obj: TSESTree.ObjectExpression): Table {
  const table: Table = { keys: new Map() };
  for (const prop of obj.properties) {addTableKey(prop, table);}
  return table;
}

function addTableKey(prop: TSESTree.ObjectLiteralElement, table: Table): void {
  if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {return;}
  if (prop.value.type === 'FunctionExpression' || prop.value.type === 'ArrowFunctionExpression') {
    table.keys.set(prop.key.name, prop.value);
  }
}

function visitProgram(bag: CallBag): void {
  const visitCalls = (node: TSESTree.Node, owner: string | null): void => {
    if (node.type === 'CallExpression') {noteCall(node, owner, bag);}
    visitChildren(node, owner, visitCalls);
  };
  for (const [name, fn] of bag.functions) {visitCalls(fn.body, name);}
  for (const stmt of bag.program.body) {
    if (stmt.type !== 'FunctionDeclaration') {visitCalls(stmt, null);}
  }
}

function visitChildren(
  node: TSESTree.Node,
  owner: string | null,
  visitCalls: (node: TSESTree.Node, owner: string | null) => void,
): void {
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'range' || key === 'parent') {continue;}
    const child: unknown = (node as unknown as Record<string, unknown>)[key];
    visitChild(child, owner, visitCalls);
  }
}

function visitChild(
  child: unknown,
  owner: string | null,
  visitCalls: (node: TSESTree.Node, owner: string | null) => void,
): void {
  if (Array.isArray(child)) {
    for (const item of child) {
      if (isAstNode(item)) {visitCalls(item, owner);}
    }
    return;
  }
  if (isAstNode(child)) {visitCalls(child, owner);}
}

function noteCall(call: TSESTree.CallExpression, owner: string | null, bag: CallBag): void {
  const callee = stripNode(call.callee);
  if (callee.type === 'MemberExpression') {
    noteMemberCall(call, callee, owner, bag);
    return;
  }
  noteBareCall(call, callee, bag);
}

function noteMemberCall(
  call: TSESTree.CallExpression,
  callee: TSESTree.MemberExpression,
  owner: string | null,
  bag: CallBag,
): void {
  const object = stripNode(callee.object);
  if (object.type !== 'Identifier') {return;}
  const table = bag.tables.get(object.name);
  if (table === undefined) {return;}
  const resolved = resolveKey(callee, owner, bag.program, bag.functions, table);
  pushResolveEvents(resolved, call, bag);
  for (const target of resolved.targets) {pushTarget(call, target, table, bag);}
}

function pushResolveEvents(
  resolved: { dynamic: boolean; unresolved: boolean },
  call: TSESTree.CallExpression,
  bag: CallBag,
): void {
  if (resolved.dynamic) {
    bag.events.push({ kind: 'dynamic-property', file: bag.file, line: lineOf(call), reason: 'computed handler key' });
  }
  if (resolved.unresolved) {
    bag.events.push({ kind: 'unknown-callee', file: bag.file, line: lineOf(call), reason: 'unknown callee' });
  }
}

function pushTarget(call: TSESTree.CallExpression, target: string, table: Table, bag: CallBag): void {
  bag.edges.push({ line: lineOf(call), target });
  const fn = table.keys.get(target);
  if (fn !== undefined && functionSinksRequest(fn)) {
    bag.findings.push({ file: bag.file, line: lineOf(call), target });
  }
}

function noteBareCall(call: TSESTree.CallExpression, callee: TSESTree.Node, bag: CallBag): void {
  if (callee.type !== 'Identifier' || bag.functions.has(callee.name) || bag.tables.has(callee.name)) {return;}
  const known = new Set(['require', 'db']);
  if (!known.has(callee.name)) {
    bag.events.push({ kind: 'unknown-callee', file: bag.file, line: lineOf(call), reason: 'unknown callee' });
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
