import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

/** Phase 255. One route record shared by later consumers. */
export const ROUTE_FLAG = 'FULLSHIELD_EXPERIMENTAL_ROUTEMODEL';

export function routesEnabled(): boolean {
  return process.env[ROUTE_FLAG] === '1';
}

export type AuthState = 'present' | 'absent' | 'unknown';

export interface RouteRecord {
  method: string;
  fullPath: string;
  file: string;
  line: number;
  handlerFn: string;
  middlewareChain: string[];
  authState: AuthState;
  validators: string[];
  framework: string;
}

interface Mount {
  router: string;
  prefix: string;
  middleware: string[];
  child: string;
  file: string;
}

interface Endpoint {
  router: string;
  method: string;
  path: string;
  middleware: string[];
  handler: string;
  file: string;
  line: number;
}

interface FileFacts {
  file: string;
  imports: Map<string, string>;
  exports: Map<string, string>;
  mounts: Mount[];
  endpoints: Endpoint[];
  routers: Set<string>;
}

const METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);

function literal(node: TSESTree.Node | undefined): string | undefined {
  if (node?.type === 'Literal' && typeof node.value === 'string') {return node.value;}
  return undefined;
}

function ident(node: TSESTree.Node | undefined): string | undefined {
  if (node?.type === 'Identifier') {return node.name;}
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

function recordImport(facts: FileFacts, stmt: TSESTree.ProgramStatement): void {
  if (stmt.type !== 'ImportDeclaration' || typeof stmt.source.value !== 'string') {return;}
  for (const spec of stmt.specifiers) {
    if (spec.type === 'ImportSpecifier') {facts.imports.set(spec.local.name, stmt.source.value);}
  }
}

function recordRouterDecl(facts: FileFacts, decl: TSESTree.VariableDeclarator): void {
  if (decl.id.type !== 'Identifier' || decl.init === null || decl.init.type !== 'CallExpression') {return;}
  const callee = decl.init.callee;
  if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && callee.property.name === 'Router') {
    facts.routers.add(decl.id.name);
  }
  if (callee.type === 'Identifier' && callee.name === 'express') {facts.routers.add(decl.id.name);}
}

function recordRouters(facts: FileFacts, stmt: TSESTree.ProgramStatement): void {
  if (stmt.type !== 'VariableDeclaration') {return;}
  for (const decl of stmt.declarations) {recordRouterDecl(facts, decl);}
}

function recordExport(facts: FileFacts, stmt: TSESTree.ProgramStatement): void {
  if (stmt.type !== 'ExportNamedDeclaration' || stmt.declaration?.type !== 'VariableDeclaration') {return;}
  for (const decl of stmt.declaration.declarations) {
    if (decl.id.type === 'Identifier') {facts.exports.set(decl.id.name, decl.id.name);}
  }
}

function argNames(args: TSESTree.CallExpression['arguments']): string[] {
  const names: string[] = [];
  for (const arg of args) {
    if (arg.type === 'SpreadElement') {continue;}
    const name = ident(arg);
    if (name !== undefined) {names.push(name);}
  }
  return names;
}

type RouterCall = TSESTree.CallExpression & {
  callee: TSESTree.MemberExpression & { object: TSESTree.Identifier; property: TSESTree.Identifier };
};

function isRouterCall(node: TSESTree.Node): node is RouterCall {
  return node.type === 'CallExpression'
    && node.callee.type === 'MemberExpression'
    && node.callee.object.type === 'Identifier'
    && node.callee.property.type === 'Identifier';
}

function recordUse(facts: FileFacts, file: string, router: string, node: RouterCall): void {
  const prefix = literal(node.arguments[0]) ?? '';
  const names = argNames(node.arguments.slice(1));
  const child = names.at(-1);
  if (child === undefined) {return;}
  facts.mounts.push({
    router,
    prefix,
    middleware: names.slice(0, -1),
    child,
    file,
  });
  facts.routers.add(child);
  facts.routers.add(router);
}

function recordEndpoint(facts: FileFacts, file: string, router: string, method: string, node: RouterCall): void {
  const path = literal(node.arguments[0]) ?? '/';
  const names = argNames(node.arguments.slice(1));
  const handler = names.at(-1) ?? 'anonymous';
  facts.endpoints.push({
    router,
    method: method.toUpperCase(),
    path,
    middleware: names.slice(0, -1),
    handler,
    file,
    line: node.loc?.start.line ?? 1,
  });
  facts.routers.add(router);
}

function recordRouteCall(facts: FileFacts, file: string, node: TSESTree.Node): void {
  if (!isRouterCall(node)) {return;}
  const router = node.callee.object.name;
  const method = node.callee.property.name;
  if (method === 'use') {recordUse(facts, file, router, node);}
  if (METHODS.has(method)) {recordEndpoint(facts, file, router, method, node);}
}

function visitRoutes(facts: FileFacts, file: string, node: TSESTree.Node): void {
  recordRouteCall(facts, file, node);
  walkAst(node, (child) => { visitRoutes(facts, file, child); });
}

function parseFile(file: string, source: string): FileFacts {
  const facts: FileFacts = {
    file,
    imports: new Map(),
    exports: new Map(),
    mounts: [],
    endpoints: [],
    routers: new Set(),
  };
  const program = parse(source, {
    loc: true,
    range: false,
    jsx: false,
    comment: false,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  });
  for (const stmt of program.body) {
    recordImport(facts, stmt);
    recordRouters(facts, stmt);
    recordExport(facts, stmt);
  }
  visitRoutes(facts, file, program);
  return facts;
}

function joinPath(prefix: string, path: string): string {
  const left = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  const right = path.startsWith('/') ? path : `/${path}`;
  const joined = `${left}${right}`;
  return joined.length === 0 ? '/' : joined;
}

function authOf(middleware: readonly string[]): AuthState {
  if (middleware.some((name) => /auth/i.test(name))) {return 'present';}
  if (middleware.length === 0) {return 'unknown';}
  return 'absent';
}

export function buildRoutes(files: readonly { file: string; source: string }[]): RouteRecord[] {
  if (!routesEnabled()) {return [];}
  const parsed = files.map((file) => parseFile(file.file, file.source));
  const byFile = new Map(parsed.map((facts) => [facts.file, facts]));
  const resolve = (file: string, name: string): { file: string; name: string } => {
    const facts = byFile.get(file);
    const spec = facts?.imports.get(name);
    if (spec === undefined || facts === undefined) {return { file, name };}
    const target = [...byFile.keys()].find((candidate) => spec.includes(candidate.replace(/\.js$/, '')) || candidate.endsWith(spec.replace(/^\.\//, '')));
    return { file: target ?? file, name };
  };

  const routes: RouteRecord[] = [];
  const walk = (file: string, router: string, prefix: string, inherited: string[]): void => {
    const facts = byFile.get(file);
    if (facts === undefined) {return;}
    for (const endpoint of facts.endpoints) {
      if (endpoint.router !== router) {continue;}
      const chain = [...inherited, ...endpoint.middleware];
      routes.push({
        method: endpoint.method,
        fullPath: joinPath(prefix, endpoint.path),
        file: endpoint.file,
        line: endpoint.line,
        handlerFn: endpoint.handler,
        middlewareChain: chain,
        authState: authOf(chain),
        validators: chain.filter((name) => /valid/i.test(name)),
        framework: 'express',
      });
    }
    for (const mount of facts.mounts) {
      if (mount.router !== router) {continue;}
      const child = resolve(file, mount.child);
      walk(child.file, child.name, joinPath(prefix, mount.prefix), [...inherited, ...mount.middleware]);
    }
  };

  for (const facts of parsed) {
    for (const router of facts.routers) {
      const mounted = parsed.some((other) => other.mounts.some((mount) => resolve(other.file, mount.child).name === router && resolve(other.file, mount.child).file === facts.file));
      if (!mounted) {walk(facts.file, router, '', []);}
    }
  }
  return routes;
}
