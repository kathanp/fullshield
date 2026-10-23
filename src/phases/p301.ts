import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, walkAst, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SERVERLESS';

export interface ServerlessFinding {
  file: string;
  line: number;
  origin: 'request' | 'event' | 'environment';
  severity: 'high' | 'medium' | 'info';
  trigger: string;
  route: string | null;
}

interface Trigger {
  handler: string;
  kind: 'http' | 'cron' | 'unknown';
  path: string | null;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeServerless(source: string, manifest: string | null, options?: { file?: string }): { findings: ServerlessFinding[]; events: UnsoundEvent[]; routes: string[] } {
  if (!enabled()) {return { findings: [], events: [], routes: [] };}
  const file = options?.file ?? 'inline.js';
  const program = parseProgram(source);
  if (program === null) {return { findings: [], events: [], routes: [] };}
  const events: UnsoundEvent[] = [];
  const triggers = loadTriggers(manifest, file, events);
  const exports = exportedFunctions(program);
  const findings: ServerlessFinding[] = [];
  const routes: string[] = [];
  const out: ServerlessOut = { file, findings, routes };
  for (const trigger of triggers) {noteTrigger(trigger, exports, program, out);}
  return { findings, events, routes };
}

function loadTriggers(manifest: string | null, file: string, events: UnsoundEvent[]): Trigger[] {
  if (manifest === null || manifest.trim() === '') {return [{ handler: '*', kind: 'unknown', path: null }];}
  const parsed = parseYaml(manifest);
  if (parsed === null) {
    events.push({ kind: 'unresolved-import', file, line: 1, reason: 'manifest parse' });
    return [{ handler: '*', kind: 'unknown', path: null }];
  }
  return triggersOf(parsed);
}

interface ServerlessOut {
  file: string;
  findings: ServerlessFinding[];
  routes: string[];
}

function noteTrigger(trigger: Trigger, exports: ReadonlyMap<string, TSESTree.Node>, program: TSESTree.Program, out: ServerlessOut): void {
  const name = trigger.handler.split('.').pop() ?? trigger.handler;
  const target = triggerTarget(trigger, name, exports, program);
  if (target === null) {return;}
  const sink = sinkOf(target);
  if (sink === null || (sink.environment && !sink.request)) {return;}
  out.routes.push(trigger.path ?? name);
  out.findings.push(serverlessFinding(trigger, name, sink, out.file));
}

function triggerTarget(trigger: Trigger, name: string, exports: ReadonlyMap<string, TSESTree.Node>, program: TSESTree.Program): TSESTree.Node | null {
  if (trigger.handler === '*') {return program;}
  return exports.get(name) ?? null;
}

function serverlessFinding(trigger: Trigger, name: string, sink: { line: number }, file: string): ServerlessFinding {
  const http = trigger.kind === 'http';
  return {
    file,
    line: sink.line,
    origin: http ? 'request' : 'event',
    severity: http ? 'high' : 'medium',
    trigger: trigger.kind,
    route: trigger.handler === '*' ? null : name,
  };
}

function sinkOf(node: TSESTree.Node): { line: number; request: boolean; environment: boolean } | null {
  let line = 0;
  let request = false;
  let environment = false;
  walkAst(node, (current) => {
    if (current.type !== 'CallExpression') {return;}
    const callee = stripNode(current.callee);
    const name = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' ? propName(callee) : null;
    if (name !== 'exec' && name !== 'execSync' && name !== 'fetch') {return;}
    const arg = current.arguments[0];
    if (arg === undefined) {return;}
    if (name === 'fetch' && isEnv(arg)) {environment = true; return;}
    if (name === 'exec' || name === 'execSync') {
      line = lineOf(current);
      request = usesRequestField(arg) || !isEnv(arg);
    }
  });
  if (line === 0) {return null;}
  return { line, request, environment };
}

function usesRequestField(node: TSESTree.Node): boolean {
  const fields = new Set(['body', 'queryStringParameters', 'pathParameters', 'headers', 'url']);
  let found = false;
  walkAst(node, (current) => {
    if (current.type === 'MemberExpression' && current.property.type === 'Identifier' && fields.has(current.property.name)) {found = true;}
    if (current.type === 'Identifier' && (current.name === 'request' || current.name === 'req')) {found = true;}
  });
  return found;
}

function isEnv(node: TSESTree.Node): boolean {
  return node.type === 'MemberExpression' && node.object.type === 'Identifier' && node.object.name === 'env';
}

function exportedFunctions(program: TSESTree.Program): Map<string, TSESTree.Node> {
  const names = new Map<string, TSESTree.Node>();
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {names.set(stmt.id.name, stmt);}
    if (stmt.type === 'ExportNamedDeclaration' && stmt.declaration?.type === 'FunctionDeclaration' && stmt.declaration.id !== null) {
      names.set(stmt.declaration.id.name, stmt.declaration);
    }
    if (stmt.type === 'ExportDefaultDeclaration' && stmt.declaration.type === 'ObjectExpression') {
      for (const prop of stmt.declaration.properties) {
        if (prop.type === 'Property' && prop.key.type === 'Identifier') {names.set(prop.key.name, prop.value);}
      }
    }
  }
  return names;
}

function triggersOf(root: Record<string, unknown>): Trigger[] {
  const triggers: Trigger[] = [];
  const visit = (node: unknown, handler: string | null): void => {
    visitTrigger(node, handler, triggers, visit);
  };
  visit(root, null);
  return triggers;
}

function visitTrigger(
  node: unknown,
  handler: string | null,
  triggers: Trigger[],
  visit: (node: unknown, handler: string | null) => void,
): void {
  if (Array.isArray(node)) {
    for (const item of node) {visit(item, handler);}
    return;
  }
  if (typeof node !== 'object' || node === null) {return;}
  const record = node as Record<string, unknown>;
  const nextHandler = handlerName(record, handler);
  noteHttp(record, nextHandler, triggers);
  noteCron(record, nextHandler, triggers);
  for (const value of Object.values(record)) {visit(value, nextHandler);}
}

function handlerName(record: Record<string, unknown>, handler: string | null): string | null {
  if (typeof record.Handler === 'string') {return record.Handler;}
  if (typeof record.handler === 'string') {return record.handler;}
  return handler;
}

function noteHttp(record: Record<string, unknown>, nextHandler: string | null, triggers: Trigger[]): void {
  const type = typeof record.Type === 'string' ? record.Type : '';
  if (type !== 'Api' && type !== 'HttpApi' && record.http === undefined) {return;}
  const path = nestedString(record.Properties, 'Path') ?? nestedString(record.http, 'path');
  triggers.push({ handler: nextHandler ?? '*', kind: 'http', path });
}

function noteCron(record: Record<string, unknown>, nextHandler: string | null, triggers: Trigger[]): void {
  const type = typeof record.Type === 'string' ? record.Type : '';
  if (type !== 'Schedule' && record.schedule === undefined) {return;}
  triggers.push({ handler: nextHandler ?? '*', kind: 'cron', path: null });
}

function nestedString(node: unknown, key: string): string | null {
  if (typeof node !== 'object' || node === null || Array.isArray(node)) {return null;}
  const value = (node as Record<string, unknown>)[key];
  return typeof value === 'string' ? value : null;
}

function parseYaml(text: string): Record<string, unknown> | null {
  if (text.includes('\t') || text.includes(':::')) {return null;}
  const lines = text.split('\n').map((line) => ({ indent: /^ */.exec(line)?.[0].length ?? 0, text: line.trim() })).filter((line) => line.text.length > 0 && !line.text.startsWith('#'));
  const index = { i: 0 };
  const parsed = parseBlock(lines, index, 0);
  return parsed;
}

function parseBlock(lines: readonly { indent: number; text: string }[], index: { i: number }, indent: number): Record<string, unknown> | null {
  const obj: Record<string, unknown> = {};
  while (index.i < lines.length) {
    const line = lines[index.i];
    if (line === undefined || line.indent < indent) {break;}
    if (line.indent !== indent || line.text.startsWith('- ')) {return null;}
    index.i += 1;
    const colon = line.text.indexOf(':');
    if (colon < 0) {return null;}
    const key = line.text.slice(0, colon).trim();
    const rest = line.text.slice(colon + 1).trim();
    if (rest.length > 0) {obj[key] = rest; continue;}
    const next = lines[index.i];
    if (next !== undefined && next.text.startsWith('- ')) {
      const list = parseList(lines, index, next.indent);
      if (list === null) {return null;}
      obj[key] = list;
      continue;
    }
    if (next !== undefined && next.indent > indent) {
      const child = parseBlock(lines, index, next.indent);
      if (child === null) {return null;}
      obj[key] = child;
      continue;
    }
    obj[key] = '';
  }
  return obj;
}

function parseList(lines: readonly { indent: number; text: string }[], index: { i: number }, indent: number): unknown[] | null {
  const items: unknown[] = [];
  while (index.i < lines.length) {
    const line = lines[index.i];
    if (line === undefined || line.indent < indent) {break;}
    if (!line.text.startsWith('- ')) {break;}
    index.i += 1;
    const body = line.text.slice(2).trim();
    const colon = body.indexOf(':');
    if (colon < 0) {items.push(body); continue;}
    const key = body.slice(0, colon).trim();
    const rest = body.slice(colon + 1).trim();
    if (rest.length > 0) {items.push({ [key]: rest }); continue;}
    const next = lines[index.i];
    if (next !== undefined && next.indent > indent && !next.text.startsWith('- ')) {
      const child = parseBlock(lines, index, next.indent);
      if (child === null) {return null;}
      items.push({ [key]: child });
      continue;
    }
    items.push({ [key]: '' });
  }
  return items;
}
