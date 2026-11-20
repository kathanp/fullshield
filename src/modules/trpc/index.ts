import { readFile } from 'node:fs/promises';
import { isAbsolute, join, relative } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';
import { calleeName, isFunctionNode, propName, walk } from '../sast/ast.js';
import { parseSource } from '../sast/fileScan.js';
import type { AstNode } from '../sast/types.js';

export const TRPC_FLAG = 'FULLSHIELD_EXPERIMENTAL_TRPC';

const SHELL = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']);
const PATHS = new Set(['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream', 'sendFile']);
const SQL = new Set(['query', 'execute']);
const SSRF = new Set(['fetch', 'request', 'get', 'post', 'put', 'patch', 'delete']);
const HTTP_LIBS = /^(axios|http|https|needle|got|request|superagent|undici)$/;
const CLEARED = new Set(['Number', 'parseInt', 'parseFloat', 'Boolean']);

export interface TrpcSource {
  file: string;
  source: string;
}

interface Flow {
  root: AstNode;
  names: Set<string>;
  payloadRoots: Set<string>;
  cleared: Set<string>;
}

function lineOf(node: AstNode): number {
  return node.loc?.start.line ?? 1;
}

function exprKey(node: AstNode | undefined): string | undefined {
  if (node === undefined) {return undefined;}
  if (node.type === 'Identifier') {return node.name;}
  if (node.type === 'MemberExpression' && node.computed !== true && node.object.type === 'Identifier') {
    const name = propName(node);
    return name === undefined ? undefined : `${node.object.name}.${name}`;
  }
  return undefined;
}

function blockReturns(node: AstNode): boolean {
  if (node.type === 'ReturnStatement' || node.type === 'ThrowStatement') {return true;}
  if (node.type !== 'BlockStatement') {return false;}
  return node.body.some((stmt) => stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement');
}

function guardedKeys(root: AstNode): Set<string> {
  const keys = new Set<string>();
  walk(root, (node) => {
    if (node.type !== 'IfStatement') {return;}
    const test = node.test.type === 'UnaryExpression' && node.test.operator === '!' ? node.test.argument : node.test;
    if (test.type !== 'CallExpression') {return;}
    const name = calleeName(test);
    if (name !== 'includes' && name !== 'has') {return;}
    if (!blockReturns(node.consequent)) {return;}
    const arg = test.arguments[0];
    const key = arg === undefined || arg.type === 'SpreadElement' ? undefined : exprKey(arg);
    if (key !== undefined) {keys.add(key);}
  });
  return keys;
}

function isInputMember(node: AstNode, flow: Flow): boolean {
  return node.type === 'MemberExpression'
    && propName(node) === 'input'
    && node.object.type === 'Identifier'
    && flow.payloadRoots.has(node.object.name);
}

function taintedCall(node: AstNode, flow: Flow): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name !== undefined && CLEARED.has(name)) {return false;}
  if (name !== 'parse') {return false;}
  return node.arguments.some((arg) => arg.type !== 'SpreadElement' && taintedExpr(arg, flow));
}

function taintedExpr(node: AstNode | undefined, flow: Flow): boolean {
  if (node === undefined || node.type === 'SpreadElement' || node.type === 'Literal') {return false;}
  const key = exprKey(node);
  if (key !== undefined && flow.cleared.has(key)) {return false;}
  if (node.type === 'Identifier') {return flow.names.has(node.name);}
  if (node.type === 'MemberExpression') {
    if (isInputMember(node, flow)) {return true;}
    return taintedExpr(node.object, flow);
  }
  if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
    return taintedExpr(node.left, flow) || taintedExpr(node.right, flow);
  }
  if (node.type === 'TemplateLiteral') {
    return node.expressions.some((item) => taintedExpr(item, flow));
  }
  if (node.type === 'CallExpression') {return taintedCall(node, flow);}
  return false;
}

function propagate(flow: Flow): void {
  walk(flow.root, (node) => {
    if (node.type !== 'VariableDeclarator' && node.type !== 'AssignmentExpression') {return;}
    if (node.type === 'AssignmentExpression') {
      if (node.left.type === 'Identifier' && taintedExpr(node.right, flow)) {flow.names.add(node.left.name);}
      return;
    }
    if (node.init === null || node.init === undefined || !taintedExpr(node.init, flow)) {return;}
    if (node.id.type === 'Identifier') {flow.names.add(node.id.name);}
    if (node.id.type === 'ObjectPattern') {
      for (const prop of node.id.properties) {
        if (prop.type === 'Property' && prop.value.type === 'Identifier') {flow.names.add(prop.value.name);}
      }
    }
  });
}

function isSsrf(node: AstNode): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name === undefined || !SSRF.has(name)) {return false;}
  if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {return true;}
  return node.callee.type === 'MemberExpression'
    && node.callee.object.type === 'Identifier'
    && HTTP_LIBS.test(node.callee.object.name);
}

function sinkKind(node: AstNode): { ruleId: string; sink: string; cwe: string } | undefined {
  if (node.type !== 'CallExpression') {return undefined;}
  const name = calleeName(node);
  if (name === undefined) {return undefined;}
  if (SQL.has(name)) {return { ruleId: 'TRPC-SQL-001', sink: 'SQL', cwe: 'CWE-89' };}
  if (SHELL.has(name)) {return { ruleId: 'TRPC-CMD-001', sink: 'shell', cwe: 'CWE-78' };}
  if (PATHS.has(name)) {return { ruleId: 'TRPC-PATH-001', sink: 'path', cwe: 'CWE-22' };}
  if (isSsrf(node)) {return { ruleId: 'TRPC-SSRF-001', sink: 'URL', cwe: 'CWE-918' };}
  return undefined;
}

function finding(ruleId: string, sink: string, cwe: string, file: string, line: number): Finding {
  return {
    id: makeFindingId(ruleId, file, String(line)),
    ruleId,
    module: 'trpc',
    title: `tRPC procedure input reaches a ${sink} call`,
    severity: 'high',
    confidence: 'medium',
    cwe,
    file,
    line,
    message: `tRPC procedure input reaches a ${sink} call.`,
    remediation: 'Pass a checked field or a constant. Do not pass the raw procedure input into SQL, a shell, a path, or a URL.',
  };
}

function bindInput(fn: AstNode, flow: Flow): boolean {
  if (!isFunctionNode(fn)) {return false;}
  const param = fn.params[0];
  if (param === undefined) {return false;}
  if (param.type === 'Identifier') {
    flow.payloadRoots.add(param.name);
    return true;
  }
  if (param.type !== 'ObjectPattern') {return false;}
  let bound = false;
  for (const prop of param.properties) {
    if (prop.type !== 'Property') {continue;}
    const key = prop.key.type === 'Identifier' ? prop.key.name : undefined;
    if (key === 'input' && prop.value.type === 'Identifier') {
      flow.names.add(prop.value.name);
      bound = true;
    }
  }
  return bound;
}

function resolverOf(node: AstNode): AstNode | undefined {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return undefined;}
  const name = propName(node.callee);
  if (name !== 'query' && name !== 'mutation') {return undefined;}
  for (const arg of node.arguments) {
    if (isFunctionNode(arg)) {return arg;}
  }
  return undefined;
}

function collect(file: string, ast: AstNode, found: Finding[]): void {
  walk(ast, (node) => {
    const fn = resolverOf(node);
    if (fn === undefined) {return;}
    const flow: Flow = { root: fn, names: new Set(), payloadRoots: new Set(), cleared: new Set() };
    if (!bindInput(fn, flow)) {return;}
    flow.cleared = guardedKeys(fn);
    propagate(flow);
    walk(fn, (inner) => {
      const kind = sinkKind(inner);
      if (kind === undefined || inner.type !== 'CallExpression') {return;}
      const arg = inner.arguments[0];
      if (arg === undefined || arg.type === 'SpreadElement' || arg.type === 'Literal') {return;}
      if (!taintedExpr(arg, flow)) {return;}
      found.push(finding(kind.ruleId, kind.sink, kind.cwe, file, lineOf(inner)));
    });
  });
}

export async function scanTrpcSources(files: readonly TrpcSource[]): Promise<Finding[]> {
  const found: Finding[] = [];
  for (const file of files) {
    const ast = await parseSource(file.source);
    if (ast === null) {continue;}
    collect(file.file, ast, found);
  }
  const uniq = new Map<string, Finding>();
  for (const item of found) {uniq.set(`${item.ruleId}|${item.file}|${item.line}`, item);}
  return [...uniq.values()];
}

export const trpcModule: ScanModule = {
  name: 'trpc',
  async run(ctx) {
    if (process.env[TRPC_FLAG] !== '1') {return [];}
    const sources: TrpcSource[] = [];
    for (const file of ctx.files) {
      const abs = join(ctx.cwd, file);
      const rel = relative(ctx.cwd, abs);
      if (rel.startsWith('..') || isAbsolute(rel)) {continue;}
      sources.push({ file: file.split('\\').join('/'), source: await readFile(abs, 'utf8') });
    }
    return scanTrpcSources(sources);
  },
};
