import { calleeName, walk } from '../sast/ast.js';
import { parseSource } from '../sast/fileScan.js';
import type { AstNode } from '../sast/types.js';

import { HTTP_METHODS } from './spec.js';
import { joinPath, nextFilePath, normPath } from './path.js';

export interface Endpoint {
  method: string;
  path: string;
  file: string;
  line: number;
}

interface RawRoute {
  owner: string;
  method: string;
  path: string;
  file: string;
  line: number;
}

interface Mount {
  parent: string;
  prefix: string;
  child: string;
}

function lineOf(node: AstNode): number {
  return node.loc?.start.line ?? 1;
}

function skipsFramework(source: string): boolean {
  return /['"]hono['"]|['"]koa['"]|['"]@koa\/router['"]|['"]koa-router['"]/.test(source);
}

function stringArg(node: AstNode | undefined): string | undefined {
  if (node !== undefined && node.type === 'Literal' && typeof node.value === 'string') {return node.value;}
  return undefined;
}

function methodOf(name: string): string | undefined {
  if (name === 'all') {return 'ALL';}
  const upper = name.toUpperCase();
  return HTTP_METHODS.has(upper) ? upper : undefined;
}

function callRoute(node: AstNode, file: string, routes: RawRoute[], mounts: Mount[]): void {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return;}
  if (node.callee.object.type !== 'Identifier') {return;}
  const name = calleeName(node);
  if (name === undefined) {return;}
  const owner = node.callee.object.name;
  if (name === 'use') {
    const prefix = stringArg(node.arguments[0]);
    const child = node.arguments[1];
    if (prefix !== undefined && prefix.startsWith('/') && child !== undefined && child.type === 'Identifier') {
      mounts.push({ parent: owner, prefix: normPath(prefix), child: child.name });
    }
    return;
  }
  const method = methodOf(name);
  const path = stringArg(node.arguments[0]);
  if (method === undefined || path === undefined || !path.startsWith('/')) {return;}
  routes.push({ owner, method, path: normPath(path), file, line: lineOf(node) });
}

interface RouteGraph {
  routes: RawRoute[];
  mounts: Mount[];
  out: Endpoint[];
}

function expand(owner: string, prefix: string, depth: number, seen: Set<string>, graph: RouteGraph): void {
  const key = `${owner}|${prefix}`;
  if (depth > 5 || seen.has(key)) {return;}
  seen.add(key);
  for (const route of graph.routes) {
    if (route.owner !== owner) {continue;}
    graph.out.push({ method: route.method, path: joinPath(prefix, route.path), file: route.file, line: route.line });
  }
  for (const mount of graph.mounts) {
    if (mount.parent !== owner) {continue;}
    expand(mount.child, joinPath(prefix, mount.prefix), depth + 1, seen, graph);
  }
}

function callEndpoints(file: string, ast: AstNode): Endpoint[] {
  const routes: RawRoute[] = [];
  const mounts: Mount[] = [];
  walk(ast, (node) => { callRoute(node, file, routes, mounts); });
  const children = new Set(mounts.map((mount) => mount.child));
  const roots = new Set<string>();
  for (const route of routes) {
    if (!children.has(route.owner)) {roots.add(route.owner);}
  }
  for (const mount of mounts) {
    if (!children.has(mount.parent)) {roots.add(mount.parent);}
  }
  const graph: RouteGraph = { routes, mounts, out: [] };
  const seen = new Set<string>();
  for (const root of roots) {expand(root, '', 0, seen, graph);}
  return graph.out;
}

function decoratorInfo(node: AstNode): { name: string; arg?: string } | undefined {
  if (node.type !== 'Decorator') {return undefined;}
  const expr = node.expression;
  if (expr.type === 'Identifier') {return { name: expr.name };}
  if (expr.type === 'CallExpression' && expr.callee.type === 'Identifier') {
    return { name: expr.callee.name, arg: stringArg(expr.arguments[0]) };
  }
  return undefined;
}

function decoratorsOf(node: AstNode): AstNode[] {
  const record = node as AstNode & { decorators?: AstNode[] };
  return record.decorators ?? [];
}

const NEST_METHODS = new Set(['Get', 'Post', 'Put', 'Patch', 'Delete', 'Head', 'Options', 'All']);

function nestMethod(name: string): string | undefined {
  if (name === 'All') {return 'ALL';}
  const upper = name.toUpperCase();
  return HTTP_METHODS.has(upper) ? upper : undefined;
}

function nestPath(prefix: string, arg: string | undefined): string {
  if (arg === undefined || arg === '' || arg === '/') {return prefix === '' ? '/' : normPath(prefix);}
  return joinPath(prefix, arg);
}

function nestEndpoints(file: string, ast: AstNode): Endpoint[] {
  const out: Endpoint[] = [];
  walk(ast, (node) => {
    if (node.type !== 'ClassDeclaration') {return;}
    const controller = decoratorsOf(node).map(decoratorInfo).find((item) => item?.name === 'Controller');
    if (controller === undefined) {return;}
    const prefix = controller.arg ?? '';
    for (const member of node.body.body) {
      if (member.type !== 'MethodDefinition') {continue;}
      const deco = decoratorsOf(member).map(decoratorInfo).find((item) => item !== undefined && NEST_METHODS.has(item.name));
      if (deco === undefined) {continue;}
      const method = nestMethod(deco.name);
      if (method === undefined) {continue;}
      out.push({ method, path: nestPath(prefix, deco.arg), file, line: lineOf(member) });
    }
  });
  return out;
}

function nextEndpoints(file: string, ast: AstNode): Endpoint[] {
  const path = nextFilePath(file);
  if (path === undefined) {return [];}
  const out: Endpoint[] = [];
  walk(ast, (node) => {
    if (node.type !== 'ExportNamedDeclaration' || node.declaration?.type !== 'FunctionDeclaration') {return;}
    const name = node.declaration.id?.name;
    if (name === undefined) {return;}
    const method = methodOf(name.toLowerCase());
    if (method === undefined || method === 'ALL') {return;}
    out.push({ method, path, file, line: lineOf(node.declaration) });
  });
  return out;
}

export async function routesIn(file: string, source: string): Promise<Endpoint[]> {
  if (skipsFramework(source)) {return [];}
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  return [...callEndpoints(file, ast), ...nestEndpoints(file, ast), ...nextEndpoints(file, ast)];
}
