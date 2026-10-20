import { calleeName, isFunctionNode, walk } from './ast.js';
import { analyzeFile, nodeIsTainted, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const DB_METHOD =
  /^(find|findOne|findOneAnd\w+|aggregate|query|execute|exec|toArray|getBy\w+|getAll\w+|addUser|update\w+)$/;

const CSRF_NAMES = new Set(['csrftoken', 'csrfToken', '_csrf']);

export interface SwigViewTaint {
  tainted: Set<string>;
  safe: Set<string>;
  spread: boolean;
}

export function taintedSwigViews(parsed: readonly { ast: AstNode }[]): Map<string, SwigViewTaint> {
  const views = new Map<string, SwigViewTaint>();
  for (const entry of parsed) {
    const facts = analyzeFile(entry.ast);
    const dbNames = dbResultNames(entry.ast);
    walk(entry.ast, (node) => {
      if (node.type !== 'CallExpression' || calleeName(node) !== 'render') return;
      const view = viewName(node.arguments?.[0]);
      const data = node.arguments?.[1];
      if (view === undefined || data === undefined) return;
      const info = views.get(view) ?? { tainted: new Set<string>(), safe: new Set<string>(), spread: false };
      absorbLocals(data, info, facts, dbNames);
      views.set(view, info);
    });
  }
  return views;
}

export function mergeSwigViews(into: Map<string, SwigViewTaint>, extra: Map<string, SwigViewTaint>): void {
  for (const [view, info] of extra) {
    const dest = into.get(view) ?? { tainted: new Set<string>(), safe: new Set<string>(), spread: false };
    for (const name of info.tainted) {
      dest.tainted.add(name);
      dest.safe.delete(name);
    }
    for (const name of info.safe) {
      if (!dest.tainted.has(name)) dest.safe.add(name);
    }
    dest.spread = dest.spread || info.spread;
    into.set(view, dest);
  }
}

export function swigNamesForFile(file: string, views: ReadonlyMap<string, SwigViewTaint>): SwigViewTaint | undefined {
  let merged: SwigViewTaint | undefined;
  for (const [view, info] of views) {
    if (!templateMatchesView(file, view)) continue;
    if (merged === undefined) {
      merged = { tainted: new Set(info.tainted), safe: new Set(info.safe), spread: info.spread };
      continue;
    }
    for (const name of info.tainted) merged.tainted.add(name);
    for (const name of info.safe) {
      if (!merged.tainted.has(name)) merged.safe.add(name);
    }
    merged.spread = merged.spread || info.spread;
  }
  if (merged === undefined) return undefined;
  for (const name of merged.tainted) merged.safe.delete(name);
  return merged;
}

export function lineHasTracedSwig(line: string, info: SwigViewTaint): boolean {
  for (const match of line.matchAll(/\{\{\s*([A-Za-z_$][\w$]*)/g)) {
    const name = match[1];
    if (name === undefined || CSRF_NAMES.has(name)) continue;
    if (info.tainted.has(name)) return true;
    if (info.spread && !info.safe.has(name)) return true;
  }
  return false;
}

function templateMatchesView(file: string, view: string): boolean {
  const norm = file.split('\\').join('/').replace(/\.(html|swig)$/i, '');
  return norm === view || norm.endsWith(`/${view}`);
}

function viewName(node: AstNode | undefined): string | undefined {
  if (node === undefined || node.type !== 'Literal' || typeof node.value !== 'string') return undefined;
  return node.value.replace(/^\.\//, '').replace(/\.(html|swig)$/i, '');
}

function absorbLocals(
  data: AstNode,
  info: SwigViewTaint,
  facts: WeakMap<AstNode, ScopeFacts>,
  dbNames: ReadonlySet<string>,
): void {
  if (data.type !== 'ObjectExpression') return;
  for (const prop of data.properties ?? []) {
    if (prop.type === 'SpreadElement') {
      if (prop.argument !== undefined && flowsFromReqOrDb(prop.argument, facts, dbNames)) info.spread = true;
      continue;
    }
    if (prop.type !== 'Property') continue;
    const key = propertyName(prop);
    if (key === undefined) continue;
    if (flowsFromReqOrDb(prop.value, facts, dbNames)) {
      info.tainted.add(key);
      info.safe.delete(key);
    } else if (!info.tainted.has(key)) {
      info.safe.add(key);
    }
  }
}

function propertyName(prop: AstNode): string | undefined {
  if (prop.type !== 'Property') return undefined;
  const key = prop.key;
  if (key.type === 'Identifier' && prop.computed !== true) return key.name;
  if (key.type === 'Literal' && typeof key.value === 'string') return key.value;
  return undefined;
}

function flowsFromReqOrDb(
  node: AstNode | undefined,
  facts: WeakMap<AstNode, ScopeFacts>,
  dbNames: ReadonlySet<string>,
): boolean {
  if (node === undefined || isCsrfValue(node)) return false;
  if (nodeIsTainted(node, facts)) return true;
  if (mentionsReq(node)) return true;
  return isDbNode(node, dbNames);
}

function isCsrfValue(node: AstNode): boolean {
  if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression') {
    const prop = node.callee.property;
    return prop?.type === 'Identifier' && prop.name === 'csrfToken' && mentionsReq(node.callee.object);
  }
  if (node.type !== 'MemberExpression' || node.computed === true) return false;
  const prop = node.property;
  if (prop?.type !== 'Identifier' || !CSRF_NAMES.has(prop.name)) return false;
  const locals = node.object;
  return (
    locals?.type === 'MemberExpression' &&
    locals.computed !== true &&
    locals.property?.type === 'Identifier' &&
    locals.property.name === 'locals'
  );
}

function mentionsReq(node: AstNode | undefined): boolean {
  if (node === undefined) return false;
  if (node.type === 'Identifier') return node.name === 'req';
  if (node.type === 'MemberExpression') return mentionsReq(node.object);
  if (node.type === 'CallExpression') {
    return mentionsReq(node.callee) || (node.arguments ?? []).some((arg) => mentionsReq(arg));
  }
  if (node.type === 'AwaitExpression') return mentionsReq(node.argument);
  if (node.type === 'ChainExpression') return mentionsReq(node.expression);
  return false;
}

function isDbNode(node: AstNode, dbNames: ReadonlySet<string>): boolean {
  if (node.type === 'Identifier') return dbNames.has(node.name);
  if (node.type === 'MemberExpression') {
    let current: AstNode | undefined = node;
    while (current?.type === 'MemberExpression') current = current.object;
    return current?.type === 'Identifier' && dbNames.has(current.name);
  }
  if (node.type === 'AwaitExpression') return node.argument !== undefined && isDbCall(node.argument);
  if (node.type === 'CallExpression') return isDbCall(node);
  return false;
}

function isDbCall(node: AstNode): boolean {
  if (node.type !== 'CallExpression') return false;
  const name = calleeName(node);
  return name !== undefined && DB_METHOD.test(name);
}

function dbResultNames(ast: AstNode): Set<string> {
  const names = new Set<string>();
  walk(ast, (node) => {
    if (node.type !== 'CallExpression' || !isDbCall(node)) return;
    for (const arg of node.arguments ?? []) {
      if (!isFunctionNode(arg)) continue;
      const params = arg.params ?? [];
      const doc = params.length >= 2 ? params[1] : undefined;
      if (doc?.type === 'Identifier' && doc.name !== undefined) names.add(doc.name);
    }
  });
  return names;
}
