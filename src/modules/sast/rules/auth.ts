import { posix } from 'node:path';

import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { calleeName, isFunctionNode, literalString, walk } from '../ast.js';
import { collectRequires } from '../interproc.js';
import {
  handlerHasFrameworkAuth,
  isNestHttpMethod,
  isNextHandler,
  nestMethodHasGuard,
} from '../frameworks.js';
import type { AstNode, SastRule } from '../types.js';

const ROUTES = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);
const AUTH_NAME = /auth|login|requireUser|requireAuth|authenticate|authorize|passport/i;

let projectAsts = new Map<string, AstNode>();

export function setAuthProject(files: ReadonlyMap<string, AstNode> | undefined): void {
  projectAsts = new Map(files ?? []);
}

function authNames(node: TSESTree.CallExpression): string[] {
  return node.arguments.flatMap((arg) => (arg.type === 'Identifier' ? [arg.name] : []));
}

function hasEarlierRouterAuth(route: TSESTree.CallExpression, objectName: string, filename: string): boolean {
  const ast = projectAsts.get(filename);
  if (ast === undefined) {return false;}
  const start = route.range?.[0] ?? Number.POSITIVE_INFINITY;
  const routePath = literalString(route.arguments[0]) ?? '';
  let covered = false;
  walk(ast, (node) => {
    if (node.type !== 'CallExpression' || calleeName(node) !== 'use') {return;}
    if ((node.range?.[0] ?? 0) >= start) {return;}
    if (node.callee.type !== 'MemberExpression' || node.callee.object.type !== 'Identifier') {return;}
    if (node.callee.object.name !== objectName) {return;}
    if (!authNames(node).some((name) => AUTH_NAME.test(name))) {return;}
    const prefix = node.arguments[0]?.type === 'Literal' ? literalString(node.arguments[0]) : undefined;
    if (prefix === undefined || routePath === prefix || routePath.startsWith(`${prefix}/`)) {covered = true;}
  });
  return covered;
}

function resolveLocal(fromFile: string, spec: string, files: ReadonlySet<string>): string | undefined {
  if (!spec.startsWith('.')) {return undefined;}
  const base = posix.normalize(posix.join(posix.dirname(fromFile), spec));
  const candidates = [base, `${base}.js`, `${base}.ts`, `${base}.mjs`, `${base}.cjs`, `${base}/index.js`, `${base}/index.ts`];
  return candidates.find((candidate) => files.has(candidate));
}

function localFiles(file: string, files: ReadonlySet<string>): string[] {
  const ast = projectAsts.get(file);
  if (ast === undefined) {return [];}
  const out: string[] = [];
  walk(ast, (node) => {
    const spec =
      node.type === 'ImportDeclaration'
        ? literalString(node.source)
        : node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require'
          ? literalString(node.arguments[0])
          : undefined;
    if (spec === undefined || !spec.startsWith('.')) {return;}
    const resolved = resolveLocal(file, spec, files);
    if (resolved !== undefined) {out.push(resolved);}
  });
  return out;
}

/** Local imports from a mounted router, at most five hops. */
function reachableFiles(start: string, files: ReadonlySet<string>): Set<string> {
  const seen = new Set<string>();
  const queue: { file: string; depth: number }[] = [{ file: start, depth: 0 }];
  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined || seen.has(current.file) || current.depth > 5) {continue;}
    seen.add(current.file);
    if (current.depth === 5) {continue;}
    for (const next of localFiles(current.file, files)) {
      if (!seen.has(next)) {queue.push({ file: next, depth: current.depth + 1 });}
    }
  }
  return seen;
}

function inheritedFromMount(filename: string): boolean {
  const files = new Set(projectAsts.keys());
  for (const [file, ast] of projectAsts) {
    if (file === filename) {continue;}
    const imports = collectRequires(file, ast, files);
    let covered = false;
    walk(ast, (node) => {
      if (covered || node.type !== 'CallExpression' || calleeName(node) !== 'use') {return;}
      if (!authNames(node).some((name) => AUTH_NAME.test(name))) {return;}
      for (const arg of node.arguments) {
        if (arg.type !== 'Identifier') {continue;}
        const start = imports.get(arg.name)?.split('#')[0];
        if (start !== undefined && reachableFiles(start, files).has(filename)) {covered = true;}
      }
    });
    if (covered) {return true;}
  }
  return false;
}
const DB_TOUCH = new Set(['query', 'find', 'findOne', 'create', 'update', 'delete', 'save', 'insert']);

function isRouteCall(node: TSESTree.CallExpression): boolean {
  if (node.callee.type !== 'MemberExpression') {return false;}
  const name = calleeName(node);
  if (name === undefined || !ROUTES.has(name)) {return false;}
  const obj = node.callee.object;
  return obj.type === 'Identifier' && /^(app|router)$/i.test(obj.name);
}

function hasAuthMiddleware(node: TSESTree.CallExpression): boolean {
  return node.arguments.some((arg) => {
    if (arg.type === 'Identifier') {return AUTH_NAME.test(arg.name);}
    return false;
  });
}

function handlerTouchesDb(handler: AstNode): boolean {
  let touches = false;
  walk(handler, (child) => {
    if (child.type === 'CallExpression' && calleeName(child) !== undefined && DB_TOUCH.has(calleeName(child) ?? '')) {
      touches = true;
    }
  });
  return touches;
}

export const authRule: SastRule = {
  meta: {
    id: 'SAST-AUTH-001',
    title: 'Route touches data with no auth middleware',
    severity: 'low',
    cwe: 'CWE-862',
    docs: 'https://cwe.mitre.org/data/definitions/862.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression' || !isRouteCall(node)) {return;}
        if (hasAuthMiddleware(node)) {return;}
        const objectName = node.callee.type === 'MemberExpression' && node.callee.object.type === 'Identifier' ? node.callee.object.name : '';
        if (hasEarlierRouterAuth(node, objectName, ctx.filename)) {return;}
        if (inheritedFromMount(ctx.filename)) {return;}
        const handler = [...node.arguments].reverse().find((arg) => isFunctionNode(arg));
        if (handler === undefined || !handlerTouchesDb(handler)) {return;}
        const path = literalString(node.arguments[0]);
        ctx.report({
          node,
          message: `Route ${path ?? '(dynamic)'} touches database/user data with no auth middleware in the chain.`,
        });
      },
      FunctionDeclaration(node) {
        if (!isNextHandler(node) || !handlerTouchesDb(node) || handlerHasFrameworkAuth(node)) {return;}
        ctx.report({
          node,
          message: `Next.js handler ${node.type === 'FunctionDeclaration' && node.id ? node.id.name : ''} touches database/user data with no auth() / session check.`,
        });
      },
      MethodDefinition(node) {
        if (node.type !== 'MethodDefinition' || !isNestHttpMethod(node)) {return;}
        if (nestMethodHasGuard(node)) {return;}
        if (!handlerTouchesDb(node.value)) {return;}
        ctx.report({
          node,
          message: 'NestJS handler touches database/user data with no UseGuards / AuthGuard.',
        });
      },
    };
  },
};
