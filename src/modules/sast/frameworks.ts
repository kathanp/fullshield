import { calleeName, literalString, propName, REQUEST_SOURCE_PROPS, walk } from './ast.js';
import { frameworksEnabled } from './experimental.js';
import type { AstNode } from './types.js';

const HTTP = new Set(['get', 'post', 'put', 'patch', 'delete', 'all', 'head', 'options']);
const NEXT_HANDLERS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const NEST_HTTP = /^(Get|Post|Put|Patch|Delete|All|Head|Options)$/;
const NEST_INPUT = /^(Body|Query|Param|Headers)$/;
const REQ_READERS = new Set(['json', 'formData', 'text', 'arrayBuffer']);
const HONO_READERS = new Set(['query', 'param', 'header', 'json', 'parseBody', 'text']);

export interface InventoriedRoute {
  framework: string;
  method: string;
  path: string;
  line?: number;
}

function decoratorExpr(dec: AstNode): AstNode | undefined {
  if (dec.type !== 'Decorator') return undefined;
  return (dec as { expression?: AstNode }).expression;
}

export function decoratorName(dec: AstNode): string | undefined {
  const expr = decoratorExpr(dec);
  if (expr === undefined) return undefined;
  if (expr.type === 'Identifier') return expr.name;
  if (expr.type === 'CallExpression') return calleeName(expr);
  return undefined;
}

export function nodeDecorators(node: AstNode): AstNode[] {
  const decs = (node as { decorators?: AstNode[] }).decorators;
  return Array.isArray(decs) ? decs : [];
}

export function nestInputDecorator(param: AstNode): string | undefined {
  if (!frameworksEnabled()) return undefined;
  for (const dec of nodeDecorators(param)) {
    const name = decoratorName(dec);
    if (name !== undefined && NEST_INPUT.test(name)) return name;
  }
  return undefined;
}

export function nestDecoratorArgCount(param: AstNode, name: string): number {
  for (const dec of nodeDecorators(param)) {
    if (decoratorName(dec) !== name) continue;
    const expr = decoratorExpr(dec);
    if (expr?.type === 'CallExpression') return expr.arguments.length;
    return 0;
  }
  return 0;
}

function isCtxIdent(node: AstNode): boolean {
  return node.type === 'Identifier' && node.name === 'ctx';
}

function isCReq(node: AstNode): boolean {
  return (
    node.type === 'MemberExpression' &&
    node.object.type === 'Identifier' &&
    node.object.name === 'c' &&
    propName(node) === 'req'
  );
}

function isCtxRequest(node: AstNode): boolean {
  return (
    node.type === 'MemberExpression' &&
    isCtxIdent(node.object) &&
    propName(node) === 'request'
  );
}

/** Member-expression taint sources used by Koa (and similar). */
export function isFrameworkMemberTaint(node: AstNode): boolean {
  if (!frameworksEnabled() || node.type !== 'MemberExpression') return false;
  const name = propName(node);
  if (name === undefined) return false;
  if (isCtxIdent(node.object) && (REQUEST_SOURCE_PROPS.has(name) || name === 'query')) return true;
  if (isCtxRequest(node.object) && REQUEST_SOURCE_PROPS.has(name)) return true;
  return false;
}

export function isFrameworkTaintCall(node: AstNode): boolean {
  if (!frameworksEnabled() || node.type !== 'CallExpression') return false;
  const name = calleeName(node);
  if (name === undefined || node.callee.type !== 'MemberExpression') return false;
  const obj = node.callee.object;
  if (obj.type === 'Identifier' && obj.name === 'request' && REQ_READERS.has(name)) return true;
  if (obj.type === 'Identifier' && (obj.name === 'formData' || obj.name === 'searchParams') && name === 'get') {
    return true;
  }
  if (obj.type === 'MemberExpression' && propName(obj) === 'searchParams' && name === 'get') return true;
  if (isCReq(obj) && HONO_READERS.has(name)) return true;
  return false;
}

export function isFrameworkRequestObject(node: AstNode): boolean {
  if (!frameworksEnabled()) return false;
  if (node.type === 'AwaitExpression') return isFrameworkRequestObject(node.argument);
  if (node.type === 'CallExpression') {
    const name = calleeName(node);
    if (name !== 'json' && name !== 'formData') return false;
    if (node.callee.type !== 'MemberExpression') return false;
    const obj = node.callee.object;
    if (obj.type === 'Identifier' && obj.name === 'request') return true;
    return isCReq(obj);
  }
  if (node.type === 'MemberExpression') {
    const name = propName(node);
    if (name !== 'body' && name !== 'query' && name !== 'params') return false;
    return isCtxRequest(node.object) || isCtxIdent(node.object);
  }
  return false;
}

function posix(file: string): string {
  return file.replaceAll('\\', '/');
}

function nextPathFromFile(file: string): string | undefined {
  const p = posix(file);
  const app = p.match(/(?:^|\/)app\/(.*)\/route\.[cm]?[jt]sx?$/);
  if (app?.[1]) return `/${app[1]}`;
  const pages = p.match(/(?:^|\/)pages\/api\/(.*)\.[cm]?[jt]sx?$/);
  if (pages?.[1]) return `/api/${pages[1]}`;
  return undefined;
}

function joinPath(prefix: string, sub: string): string {
  const a = prefix.startsWith('/') ? prefix : `/${prefix}`;
  if (!sub || sub === '/') return a === '/' ? '/' : a;
  const b = sub.startsWith('/') ? sub : `/${sub}`;
  if (a === '/') return b;
  return `${a}${b}`;
}

function nestControllerPrefix(cls: AstNode): string {
  for (const dec of nodeDecorators(cls)) {
    if (decoratorName(dec) !== 'Controller') continue;
    const expr = decoratorExpr(dec);
    if (expr?.type === 'CallExpression') {
      const first = expr.arguments[0];
      if (first && first.type !== 'SpreadElement') return literalString(first) ?? '';
    }
  }
  return '';
}

export function inventoryRoutes(filename: string, ast: AstNode): InventoriedRoute[] {
  const routes: InventoriedRoute[] = [];
  const nextPath = nextPathFromFile(filename);

  walk(ast, (node) => {
    if (node.type === 'CallExpression') {
      const name = calleeName(node);
      if (name !== undefined && HTTP.has(name) && node.callee.type === 'MemberExpression') {
        const path = node.arguments[0] !== undefined && node.arguments[0].type !== 'SpreadElement'
          ? literalString(node.arguments[0])
          : undefined;
        if (path !== undefined) {
          const obj = node.callee.object;
          const objName = obj.type === 'Identifier' ? obj.name : '';
          const framework = /hono/i.test(filename + objName)
            ? 'hono'
            : /koa/i.test(filename + objName)
              ? 'koa'
              : 'http';
          routes.push({
            framework,
            method: name.toUpperCase(),
            path,
            line: node.loc?.start.line,
          });
        }
      }
    }

    if (node.type === 'FunctionDeclaration' && node.id !== null) {
      if (NEXT_HANDLERS.has(node.id.name) && nextPath !== undefined) {
        routes.push({
          framework: 'next',
          method: node.id.name,
          path: nextPath,
          line: node.loc?.start.line,
        });
      }
      if (
        node.params.some((p) => p.type === 'Identifier' && p.name === 'formData') &&
        node.id.name !== undefined
      ) {
        routes.push({
          framework: 'next',
          method: 'ACTION',
          path: node.id.name,
          line: node.loc?.start.line,
        });
      }
      if (node.id.name === 'handler' && nextPath !== undefined && posix(filename).includes('pages/api/')) {
        routes.push({
          framework: 'next',
          method: 'ALL',
          path: nextPath,
          line: node.loc?.start.line,
        });
      }
    }

    if (node.type === 'ClassDeclaration' || node.type === 'ClassExpression') {
      const prefix = nestControllerPrefix(node);
      for (const member of node.body.body) {
        if (member.type !== 'MethodDefinition') continue;
        const http = nodeDecorators(member).find((d) => {
          const n = decoratorName(d);
          return n !== undefined && NEST_HTTP.test(n);
        });
        if (http === undefined) continue;
        const expr = decoratorExpr(http);
        let sub = '';
        if (expr?.type === 'CallExpression') {
          const first = expr.arguments[0];
          if (first && first.type !== 'SpreadElement') sub = literalString(first) ?? '';
        }
        routes.push({
          framework: 'nest',
          method: (decoratorName(http) ?? 'GET').toUpperCase(),
          path: joinPath(prefix, sub),
          line: member.loc?.start.line,
        });
      }
    }
  });

  return routes;
}

export function isNextHandler(node: AstNode): boolean {
  if (!frameworksEnabled() || node.type !== 'FunctionDeclaration' || node.id === null) return false;
  if (!NEXT_HANDLERS.has(node.id.name)) return false;
  const parent = (node as { parent?: AstNode }).parent;
  return parent?.type === 'ExportNamedDeclaration';
}

export function isNestHttpMethod(node: AstNode): boolean {
  if (!frameworksEnabled() || node.type !== 'MethodDefinition') return false;
  return nodeDecorators(node).some((d) => {
    const n = decoratorName(d);
    return n !== undefined && NEST_HTTP.test(n);
  });
}

export function nestMethodHasGuard(node: AstNode): boolean {
  if (nodeDecorators(node).some((d) => decoratorName(d) === 'UseGuards')) return true;
  const cls = (node as { parent?: { parent?: AstNode } }).parent?.parent;
  if (cls) return nodeDecorators(cls).some((d) => decoratorName(d) === 'UseGuards');
  return false;
}

export function handlerHasFrameworkAuth(handler: AstNode): boolean {
  let yes = false;
  walk(handler, (child) => {
    if (child.type !== 'CallExpression') return;
    const name = calleeName(child);
    if (name !== undefined && /^(auth|cookies|getServerSession|getToken|requireAuth|authenticate)$/i.test(name)) {
      yes = true;
    }
  });
  return yes;
}
