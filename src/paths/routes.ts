import { collectRequires } from '../modules/sast/interproc.js';
import { calleeName, isFunctionNode, literalString, walk } from '../modules/sast/ast.js';
import type { AstNode } from '../modules/sast/types.js';
import type { AttackPathEntry } from './types.js';

const HTTP = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);
const AUTH_NAME = /auth|login|requireUser|requireAuth|authenticate|authorize|passport/i;

export interface RouteInfo {
  method: string;
  path: string;
  file: string;
  start: number;
  end: number;
  auth: 'present' | 'absent';
}

interface RawRoute {
  method: string;
  path: string;
  file: string;
  start: number;
  end: number;
  call: AstNode;
  objectName: string;
}

export function entryOf(route: RouteInfo): AttackPathEntry {
  return { method: route.method, path: route.path, auth: route.auth };
}

export function routeAt(routes: readonly RouteInfo[], file: string, line: number): RouteInfo | undefined {
  let best: RouteInfo | undefined;
  let span = Number.POSITIVE_INFINITY;
  for (const route of routes) {
    if (route.file !== file || line < route.start || line > route.end) {continue;}
    const size = route.end - route.start;
    if (size < span) {
      best = route;
      span = size;
    }
  }
  return best;
}

export function inventoryRoutes(asts: ReadonlyMap<string, AstNode>): RouteInfo[] {
  const raw: RawRoute[] = [];
  for (const [file, ast] of asts) {raw.push(...routesInFile(file, ast));}
  const covered = inheritedAuthFiles(asts);
  return raw.map((route) => ({
    method: route.method,
    path: route.path,
    file: route.file,
    start: route.start,
    end: route.end,
    auth: routeAuth(route, asts.get(route.file), covered.has(route.file)),
  }));
}

function routesInFile(file: string, ast: AstNode): RawRoute[] {
  const out: RawRoute[] = [];
  walk(ast, (node) => {
    const route = asRoute(node, file, ast);
    if (route !== undefined) {out.push(route);}
  });
  return out;
}

function asRoute(node: AstNode, file: string, ast: AstNode): RawRoute | undefined {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return undefined;}
  const method = calleeName(node);
  if (method === undefined || !HTTP.has(method)) {return undefined;}
  if (node.callee.object.type !== 'Identifier') {return undefined;}
  const pathArg = node.arguments[0];
  const path = pathArg !== undefined && pathArg.type !== 'SpreadElement' ? literalString(pathArg) : undefined;
  if (path === undefined) {return undefined;}
  const range = handlerRange(node, ast);
  return {
    method: method.toUpperCase(),
    path,
    file,
    start: range.start,
    end: range.end,
    call: node,
    objectName: node.callee.object.name,
  };
}

function handlerRange(call: AstNode, ast: AstNode): { start: number; end: number } {
  if (call.type !== 'CallExpression') {return { start: 1, end: 1 };}
  const fn = [...call.arguments].reverse().find((arg) => arg.type !== 'SpreadElement' && isFunctionNode(arg));
  if (fn !== undefined && fn.loc !== undefined) {return { start: fn.loc.start.line, end: fn.loc.end.line };}
  const named = namedHandler(call, ast);
  if (named?.loc !== undefined) {return { start: named.loc.start.line, end: named.loc.end.line };}
  const line = call.loc?.start.line ?? 1;
  return { start: line, end: call.loc?.end.line ?? line };
}

function namedHandler(call: AstNode, ast: AstNode): AstNode | undefined {
  if (call.type !== 'CallExpression') {return undefined;}
  const ident = [...call.arguments].reverse().find((arg) => arg.type === 'Identifier');
  if (ident === undefined || ident.type !== 'Identifier') {return undefined;}
  return functionNamed(ast, ident.name);
}

function functionNamed(ast: AstNode, name: string): AstNode | undefined {
  let found: AstNode | undefined;
  walk(ast, (node) => {
    if (found !== undefined) {return;}
    if (node.type === 'FunctionDeclaration' && node.id !== null && node.id.name === name) {found = node;}
  });
  return found;
}

function routeAuth(route: RawRoute, ast: AstNode | undefined, inherited: boolean): 'present' | 'absent' {
  if (inherited || (ast !== undefined && (directAuth(route.call) || earlierAuth(route, ast)))) {return 'present';}
  return 'absent';
}

function directAuth(call: AstNode): boolean {
  return call.type === 'CallExpression' && hasAuthArg(call);
}

function earlierAuth(route: RawRoute, ast: AstNode): boolean {
  if (route.call.type !== 'CallExpression') {return false;}
  const start = route.call.range?.[0] ?? Number.POSITIVE_INFINITY;
  let covered = false;
  walk(ast, (node) => {
    if (covered || !isEarlierUse(node, route.objectName, start) || !hasAuthArg(node)) {return;}
    const prefix = usePrefix(node);
    if (prefix === undefined || route.path === prefix || route.path.startsWith(`${prefix}/`)) {covered = true;}
  });
  return covered;
}

function isEarlierUse(node: AstNode, objectName: string, start: number): boolean {
  if (node.type !== 'CallExpression' || calleeName(node) !== 'use') {return false;}
  if ((node.range?.[0] ?? 0) >= start) {return false;}
  if (node.callee.type !== 'MemberExpression' || node.callee.object.type !== 'Identifier') {return false;}
  return node.callee.object.name === objectName;
}

function hasAuthArg(node: AstNode): boolean {
  if (node.type !== 'CallExpression') {return false;}
  return node.arguments.some((arg) => arg.type === 'Identifier' && AUTH_NAME.test(arg.name));
}

function usePrefix(node: AstNode): string | undefined {
  if (node.type !== 'CallExpression') {return undefined;}
  const first = node.arguments[0];
  if (first === undefined || first.type !== 'Literal') {return undefined;}
  return literalString(first);
}

function inheritedAuthFiles(asts: ReadonlyMap<string, AstNode>): Set<string> {
  const files = new Set(asts.keys());
  const covered = new Set<string>();
  for (const [file, ast] of asts) {coverMounted(file, ast, files, asts, covered);}
  return covered;
}

function coverMounted(
  file: string,
  ast: AstNode,
  files: ReadonlySet<string>,
  asts: ReadonlyMap<string, AstNode>,
  covered: Set<string>,
): void {
  const imports = collectRequires(file, ast, files);
  walk(ast, (node) => {
    if (node.type !== 'CallExpression' || calleeName(node) !== 'use' || !hasAuthArg(node)) {return;}
    for (const arg of node.arguments) {
      if (arg.type !== 'Identifier') {continue;}
      const start = imports.get(arg.name)?.split('#')[0];
      if (start === undefined) {continue;}
      for (const reached of reachableFrom(start, files, asts)) {covered.add(reached);}
    }
  });
}

function reachableFrom(
  start: string,
  files: ReadonlySet<string>,
  asts: ReadonlyMap<string, AstNode>,
): Set<string> {
  const seen = new Set<string>();
  const queue: Array<{ file: string; depth: number }> = [{ file: start, depth: 0 }];
  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined || seen.has(current.file) || current.depth > 5) {continue;}
    seen.add(current.file);
    if (current.depth === 5) {continue;}
    const ast = asts.get(current.file);
    if (ast === undefined) {continue;}
    for (const next of localImports(current.file, ast, files)) {
      if (!seen.has(next)) {queue.push({ file: next, depth: current.depth + 1 });}
    }
  }
  return seen;
}

function localImports(file: string, ast: AstNode, files: ReadonlySet<string>): string[] {
  const out: string[] = [];
  for (const target of collectRequires(file, ast, files).values()) {
    const resolved = target.split('#')[0];
    if (resolved !== undefined && resolved.length > 0) {out.push(resolved);}
  }
  return out;
}
