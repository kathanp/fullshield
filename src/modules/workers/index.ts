import { readFile } from 'node:fs/promises';
import { isAbsolute, join, relative } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';
import { calleeName, isFunctionNode, propName, walk } from '../sast/ast.js';
import { parseSource } from '../sast/fileScan.js';
import type { AstNode } from '../sast/types.js';

export const WORKERS_FLAG = 'FULLSHIELD_EXPERIMENTAL_WORKERS';

const SHELL = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']);
const PATHS = new Set(['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream', 'sendFile']);
const SQL = new Set(['query', 'execute']);
const SSRF = new Set(['fetch', 'request', 'get', 'post', 'put', 'patch', 'delete']);
const HTTP_LIBS = /^(axios|http|https|needle|got|request|superagent|undici)$/;

export interface WorkerSource {
  file: string;
  source: string;
}

interface Flow {
  root: AstNode;
  source: string;
  names: Set<string>;
  payloadRoots: Set<string>;
  payloadProp: string | undefined;
  indexedRecords: boolean;
  cleared: Set<string>;
}

function lineOf(node: AstNode): number {
  return node.loc?.start.line ?? 1;
}

function importsFrom(ast: AstNode, pkg: string): boolean {
  let found = false;
  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration' && node.source.value === pkg) {found = true;}
    if (node.type === 'CallExpression' && calleeName(node) === 'require') {
      const arg = node.arguments[0];
      if (arg !== undefined && arg.type === 'Literal' && arg.value === pkg) {found = true;}
    }
  });
  return found;
}

function functionArg(node: AstNode): AstNode | undefined {
  if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {return undefined;}
  for (const arg of node.arguments) {
    if (isFunctionNode(arg)) {return arg;}
  }
  return undefined;
}

function firstParam(fn: AstNode): string | undefined {
  if (!isFunctionNode(fn)) {return undefined;}
  const param = fn.params[0];
  return param !== undefined && param.type === 'Identifier' ? param.name : undefined;
}

function recordsLoopVars(ast: AstNode): Set<string> {
  const names = new Set<string>();
  walk(ast, (node) => {
    if (node.type !== 'ForOfStatement') {return;}
    if (node.right.type !== 'MemberExpression' || propName(node.right) !== 'Records') {return;}
    if (node.left.type !== 'VariableDeclaration') {return;}
    for (const decl of node.left.declarations) {
      if (decl.id.type === 'Identifier') {names.add(decl.id.name);}
    }
  });
  return names;
}

function isIndexedRecordsBody(node: AstNode): boolean {
  if (node.type !== 'MemberExpression' || propName(node) !== 'body') {return false;}
  const indexed = node.object;
  return indexed.type === 'MemberExpression'
    && indexed.computed === true
    && indexed.object.type === 'MemberExpression'
    && propName(indexed.object) === 'Records';
}

function hasIndexedRecordsBody(ast: AstNode): boolean {
  let found = false;
  walk(ast, (node) => {
    if (isIndexedRecordsBody(node)) {found = true;}
  });
  return found;
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

function isPayloadMember(node: AstNode, flow: Flow): boolean {
  if (node.type !== 'MemberExpression') {return false;}
  if (flow.payloadProp !== undefined && node.object.type === 'Identifier' && flow.payloadRoots.has(node.object.name) && propName(node) === flow.payloadProp) {
    return true;
  }
  return flow.indexedRecords && isIndexedRecordsBody(node);
}

function taintedExpr(node: AstNode | undefined, flow: Flow): boolean {
  if (node === undefined || node.type === 'SpreadElement' || node.type === 'Literal') {return false;}
  const key = exprKey(node);
  if (key !== undefined && flow.cleared.has(key)) {return false;}
  if (node.type === 'Identifier') {return flow.names.has(node.name);}
  if (node.type === 'MemberExpression') {
    if (isPayloadMember(node, flow)) {return true;}
    return taintedExpr(node.object, flow);
  }
  if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
    return taintedExpr(node.left, flow) || taintedExpr(node.right, flow);
  }
  if (node.type === 'TemplateLiteral') {
    return node.expressions.some((item) => taintedExpr(item, flow));
  }
  if (node.type === 'CallExpression') {
    const name = calleeName(node);
    if (name === 'Number' || name === 'parseInt' || name === 'parseFloat' || name === 'Boolean') {return false;}
    if (name === 'parse') {
      return node.arguments.some((arg) => arg.type !== 'SpreadElement' && taintedExpr(arg, flow));
    }
  }
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
  if (SQL.has(name)) {return { ruleId: 'WORKERS-SQL-001', sink: 'SQL', cwe: 'CWE-89' };}
  if (SHELL.has(name)) {return { ruleId: 'WORKERS-CMD-001', sink: 'shell', cwe: 'CWE-78' };}
  if (PATHS.has(name)) {return { ruleId: 'WORKERS-PATH-001', sink: 'path', cwe: 'CWE-22' };}
  if (isSsrf(node)) {return { ruleId: 'WORKERS-SSRF-001', sink: 'URL', cwe: 'CWE-918' };}
  return undefined;
}

function sourceLabel(source: string): string {
  if (source === 'SQS') {return 'SQS record body';}
  if (source === 'WebSocket or Socket.IO') {return 'WebSocket or Socket.IO message';}
  return `${source} job payload`;
}

function finding(ruleId: string, source: string, sink: string, cwe: string, file: string, line: number): Finding {
  const label = sourceLabel(source);
  return {
    id: makeFindingId(ruleId, file, String(line)),
    ruleId,
    module: 'workers',
    title: `${label} reaches a ${sink} call`,
    severity: 'high',
    confidence: 'medium',
    cwe,
    file,
    line,
    message: `${label} reaches a ${sink} call.`,
    remediation: 'Parse the payload and pass a checked field, or pass a constant. Do not pass the raw job, record, or message into SQL, a shell, a path, or a URL.',
  };
}

function collect(file: string, flow: Flow, found: Finding[]): void {
  flow.cleared = guardedKeys(flow.root);
  propagate(flow);
  walk(flow.root, (node) => {
    const kind = sinkKind(node);
    if (kind === undefined || node.type !== 'CallExpression') {return;}
    const arg = node.arguments[0];
    if (arg === undefined || arg.type === 'SpreadElement' || arg.type === 'Literal') {return;}
    if (!taintedExpr(arg, flow)) {return;}
    found.push(finding(kind.ruleId, flow.source, kind.sink, kind.cwe, file, lineOf(node)));
  });
}

function flowsFor(ast: AstNode): Flow[] {
  const flows: Flow[] = [];
  const bull = importsFrom(ast, 'bullmq');
  const bee = importsFrom(ast, 'bee-queue');
  const loopVars = recordsLoopVars(ast);
  if (loopVars.size > 0 || hasIndexedRecordsBody(ast)) {
    flows.push({
      root: ast,
      source: 'SQS',
      names: new Set(),
      payloadRoots: loopVars,
      payloadProp: 'body',
      indexedRecords: true,
      cleared: new Set(),
    });
  }
  walk(ast, (node) => {
    if (bull && node.type === 'NewExpression' && calleeName(node) === 'Worker') {
      const fn = functionArg(node);
      const param = fn === undefined ? undefined : firstParam(fn);
      if (fn !== undefined && param !== undefined) {
        flows.push({
          root: fn,
          source: 'BullMQ',
          names: new Set(),
          payloadRoots: new Set([param]),
          payloadProp: 'data',
          indexedRecords: false,
          cleared: new Set(),
        });
      }
    }
    if (bee && node.type === 'CallExpression' && calleeName(node) === 'process') {
      const fn = functionArg(node);
      const param = fn === undefined ? undefined : firstParam(fn);
      if (fn !== undefined && param !== undefined) {
        flows.push({
          root: fn,
          source: 'bee-queue',
          names: new Set(),
          payloadRoots: new Set([param]),
          payloadProp: 'data',
          indexedRecords: false,
          cleared: new Set(),
        });
      }
    }
    if (node.type === 'CallExpression' && (calleeName(node) === 'on' || calleeName(node) === 'addEventListener')) {
      const event = node.arguments[0];
      const fn = node.arguments[1];
      if (event !== undefined && event.type === 'Literal' && event.value === 'message' && fn !== undefined && isFunctionNode(fn)) {
        const param = firstParam(fn);
        if (param !== undefined) {
          flows.push({
            root: fn,
            source: 'WebSocket or Socket.IO',
            names: new Set([param]),
            payloadRoots: new Set(),
            payloadProp: undefined,
            indexedRecords: false,
            cleared: new Set(),
          });
        }
      }
    }
  });
  return flows;
}

export async function scanWorkersSources(files: readonly WorkerSource[]): Promise<Finding[]> {
  const found: Finding[] = [];
  for (const file of files) {
    const ast = await parseSource(file.source);
    if (ast === null) {continue;}
    for (const flow of flowsFor(ast)) {collect(file.file, flow, found);}
  }
  const uniq = new Map<string, Finding>();
  for (const item of found) {uniq.set(`${item.ruleId}|${item.file}|${item.line}`, item);}
  return [...uniq.values()];
}

export const workersModule: ScanModule = {
  name: 'workers',
  async run(ctx) {
    if (process.env[WORKERS_FLAG] !== '1') {return [];}
    const sources: WorkerSource[] = [];
    for (const file of ctx.files) {
      const abs = join(ctx.cwd, file);
      const rel = relative(ctx.cwd, abs);
      if (rel.startsWith('..') || isAbsolute(rel)) {continue;}
      sources.push({ file: file.split('\\').join('/'), source: await readFile(abs, 'utf8') });
    }
    return scanWorkersSources(sources);
  },
};
