import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, walkAst, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_NEXTAPP';

export interface NextRoute {
  file: string;
  fullPath: string;
  sources: string[];
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeNextApp(files: Readonly<Record<string, string>>, options?: { appRoot?: string }): { routes: NextRoute[]; events: UnsoundEvent[]; findings: { file: string; line: number }[] } {
  if (!enabled()) {return { routes: [], events: [], findings: [] };}
  const appRoot = options?.appRoot ?? 'app';
  const routes: NextRoute[] = [];
  const events: UnsoundEvent[] = [];
  const findings: { file: string; line: number }[] = [];
  for (const [file, source] of Object.entries(files)) {
    if (file.startsWith('pages/') || file.includes('/pages/')) {continue;}
    const compiled = compilePath(file, appRoot);
    if (compiled.kind === 'outside') {continue;}
    if (compiled.kind === 'reject') {
      events.push({ kind: 'dynamic-property', file, line: 1, reason: compiled.reason });
      continue;
    }
    const program = parseProgram(source);
    if (program === null) {continue;}
    const sources = sourcesOf(program, file, events);
    if (compiled.fileKind === 'route' || compiled.fileKind === 'page' || compiled.fileKind === 'layout') {
      routes.push({ file, fullPath: compiled.fullPath, sources });
    }
    if (sources.length > 0 && reachesSink(program)) {findings.push({ file, line: sinkLine(program) });}
  }
  return { routes, events, findings };
}

function compilePath(file: string, appRoot: string): { kind: 'route'; fullPath: string; fileKind: 'route' | 'page' | 'layout' | 'other' } | { kind: 'reject'; reason: string } | { kind: 'outside' } {
  const prefix = appRoot.endsWith('/') ? appRoot : `${appRoot}/`;
  if (!file.startsWith(prefix)) {return { kind: 'outside' };}
  const parts = file.slice(prefix.length).split('/');
  const base = parts.pop() ?? '';
  const fileKind = base.startsWith('route.') ? 'route' : base.startsWith('page.') ? 'page' : base.startsWith('layout.') ? 'layout' : 'other';
  const pieces: string[] = [];
  const groups: string[] = [];
  for (const part of parts) {
    if (part.startsWith('@') && part.includes('[')) {return { kind: 'reject', reason: 'slot dynamic' };}
    if (part.startsWith('@')) {continue;}
    if (part.startsWith('(.)') || part.startsWith('(..)') || part.startsWith('(...)')) {
      const rest = part.slice(part.indexOf(')') + 1);
      if (rest.length > 0) {pieces.push(rest);}
      continue;
    }
    if (part.startsWith('(') && part.endsWith(')')) {
      const name = part.slice(1, -1);
      if (name.startsWith('.')) {continue;}
      if (groups.includes(name)) {return { kind: 'reject', reason: 'duplicate group' };}
      groups.push(name);
      continue;
    }
    pieces.push(part);
  }
  return { kind: 'route', fullPath: `/${pieces.join('/')}`, fileKind };
}

function sourcesOf(program: TSESTree.Program, file: string, events: UnsoundEvent[]): string[] {
  const sources = new Set<string>();
  walkAst(program, (node) => {
    if ((node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression')) {
      for (const param of node.params) {
        if (param.type === 'Identifier' && (param.name === 'request' || param.name === 'Request')) {sources.add('request');}
        if (param.type === 'ObjectPattern') {
          for (const item of param.properties) {
            if (item.type === 'Property' && item.key.type === 'Identifier') {
              if (item.key.name === 'searchParams' || item.key.name === 'params' || item.key.name === 'request') {sources.add(item.key.name);}
            }
          }
        }
      }
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && (node.callee.name === 'headers' || node.callee.name === 'cookies')) {
      sources.add(node.callee.name);
    }
  });
  for (const name of ['params', 'searchParams']) {
    if (sources.has(name) && usedWithoutAwait(program, name)) {
      events.push({ kind: 'unknown-callee', file, line: 1, reason: 'promise form' });
    }
  }
  return [...sources];
}

function usedWithoutAwait(program: TSESTree.Program, name: string): boolean {
  let awaited = false;
  let used = false;
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'AwaitExpression' && node.argument.type === 'Identifier' && node.argument.name === name) {
      awaited = true;
      return;
    }
    if (node.type === 'MemberExpression' && node.object.type === 'Identifier' && node.object.name === name) {used = true;}
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range') {continue;}
      const child: unknown = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(child)) {
        for (const item of child) {if (isNode(item)) {visit(item);}}
      } else if (isNode(child)) {visit(child);}
    }
  };
  visit(program);
  return used && !awaited;
}

function isNode(value: unknown): value is TSESTree.Node {
  return typeof value === 'object' && value !== null && 'type' in value && typeof value.type === 'string';
}

function reachesSink(program: TSESTree.Program): boolean {
  let found = false;
  walkAst(program, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const prop = node.callee.property;
      if (prop.type === 'Identifier' && (prop.name === 'query' || prop.name === 'exec')) {found = true;}
    }
  });
  return found;
}

function sinkLine(program: TSESTree.Program): number {
  let line = 1;
  walkAst(program, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {line = lineOf(node);}
  });
  return line;
}
