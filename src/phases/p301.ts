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
  let triggers: Trigger[] = [];
  const events: UnsoundEvent[] = [];
  if (manifest === null || manifest.trim() === '') {
    triggers = [{ handler: '*', kind: 'unknown', path: null }];
  } else {
    const parsed = parseYaml(manifest);
    if (parsed === null) {
      events.push({ kind: 'unresolved-import', file, line: 1, reason: 'manifest parse' });
      triggers = [{ handler: '*', kind: 'unknown', path: null }];
    } else {
      triggers = triggersOf(parsed);
    }
  }
  const exports = exportedFunctions(program);
  const findings: ServerlessFinding[] = [];
  const routes: string[] = [];
  for (const trigger of triggers) {
    const name = trigger.handler.split('.').pop() ?? trigger.handler;
    if (trigger.handler !== '*' && !exports.has(name)) {continue;}
    const fn = trigger.handler === '*' ? null : exports.get(name) ?? null;
    if (fn === null && trigger.handler !== '*') {continue;}
    const target = fn ?? program;
    const sink = sinkOf(target);
    if (sink === null) {continue;}
    const http = trigger.kind === 'http';
    const environment = sink.environment;
    if (environment && !sink.request) {continue;}
    routes.push(trigger.path ?? name);
    findings.push({
      file,
      line: sink.line,
      origin: http ? 'request' : 'event',
      severity: http ? 'high' : 'medium',
      trigger: trigger.kind,
      route: trigger.handler === '*' ? null : name,
    });
  }
  return { findings, events, routes };
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
    if (Array.isArray(node)) {
      for (const item of node) {visit(item, handler);}
      return;
    }
    if (typeof node !== 'object' || node === null) {return;}
    const record = node as Record<string, unknown>;
    const nextHandler = typeof record.Handler === 'string' ? record.Handler : typeof record.handler === 'string' ? record.handler : handler;
    const type = typeof record.Type === 'string' ? record.Type : '';
    if (type === 'Api' || type === 'HttpApi' || record.http !== undefined) {
      const path = nestedString(record.Properties, 'Path') ?? nestedString(record.http, 'path');
      triggers.push({ handler: nextHandler ?? '*', kind: 'http', path });
    }
    if (type === 'Schedule' || record.schedule !== undefined) {
      triggers.push({ handler: nextHandler ?? '*', kind: 'cron', path: null });
    }
    for (const value of Object.values(record)) {visit(value, nextHandler);}
  };
  visit(root, null);
  return triggers;
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
