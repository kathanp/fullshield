import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { parseProgram, walkAst, type UnsoundEvent } from './p271.js';
import { satisfiesRange, selectRow, type ModelRow } from './p310.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_METAFRAME';

export interface MetaRoute {
  file: string;
  framework: string;
  fullPath: string;
  finding: boolean;
}

const ROWS: Record<string, ModelRow[]> = {
  remix: [{ id: 'remix-2', appliesTo: '>=2 <3' }],
  sveltekit: [{ id: 'sveltekit-2', appliesTo: '>=2 <3' }],
  nuxt: [{ id: 'nuxt-3', appliesTo: '>=3 <4' }],
};

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeMeta(files: Readonly<Record<string, string>>, options: { framework: string; version: string; routesDir?: string; packagePath?: string; rows?: readonly ModelRow[] }): { routes: MetaRoute[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { routes: [], events: [] };}
  const rows = options.rows ?? ROWS[options.framework] ?? [];
  const selected = selectRow(rows, options.version, options.packagePath ?? options.framework);
  const verkey = process.env.FULLSHIELD_EXPERIMENTAL_VERKEY === '1';
  const supported = verkey ? selected.row !== null && !selected.fallback : rows.some((row) => row.appliesTo !== undefined && satisfiesRange(options.version, row.appliesTo));
  if (!supported) {return { routes: [], events: verkey ? selected.events : [{ kind: 'unknown-callee', file: options.framework, line: 1, reason: 'version-gap' }] };}
  const routes: MetaRoute[] = [];
  const events: UnsoundEvent[] = [];
  const dir = options.routesDir;
  for (const [file, source] of Object.entries(files)) {
    if (dir !== undefined && !file.startsWith(dir)) {continue;}
    const kinds = grammars(file, source);
    if (kinds.length > 1) {
      events.push({ kind: 'unknown-callee', file, line: 1, reason: 'two grammars' });
      continue;
    }
    const kind = kinds[0];
    if (kind === undefined || (options.framework !== 'auto' && kind !== options.framework)) {continue;}
    const program = parseProgram(source);
    if (program === null) {continue;}
    const fullPath = pathFor(kind, file, dir);
    const finding = reaches(program) && (sameRequestLocals(program) || usesSource(program));
    routes.push({ file, framework: kind, fullPath, finding });
  }
  return { routes, events };
}

function grammars(file: string, source: string): string[] {
  const found: string[] = [];
  if (file.includes('/routes/') && (source.includes('export function loader') || source.includes('export function action'))) {found.push('remix');}
  if (file.includes('+page') || file.includes('+server')) {found.push('sveltekit');}
  if (source.includes('defineEventHandler')) {found.push('nuxt');}
  return found;
}

function pathFor(kind: string, file: string, dir: string | undefined): string {
  const root = dir ?? (kind === 'sveltekit' ? 'src/routes' : kind === 'nuxt' ? 'server' : 'app/routes');
  let rel = file.startsWith(`${root}/`) ? file.slice(root.length) : file;
  rel = rel.replace(/\.(t|j)sx?$/, '');
  if (kind === 'remix') {
    const pieces = rel.split('/').flatMap((part) => part.split('.')).filter((part) => part.length > 0).map((part) => part.startsWith('$') ? `:${part.slice(1)}` : part);
    return `/${pieces.join('/')}`;
  }
  if (kind === 'sveltekit') {
    rel = rel.replace(/\/\+(page|server)(\.server)?$/, '');
    const pieces = rel.split('/').filter((part) => part.length > 0).map((part) => part.startsWith('[') && part.endsWith(']') ? `:${part.slice(1, -1)}` : part);
    return `/${pieces.join('/')}`;
  }
  rel = rel.replace(/\/index$/, '');
  const pieces = rel.split('/').filter((part) => part.length > 0).map((part) => part.startsWith('[') && part.endsWith(']') ? `:${part.slice(1, -1)}` : part);
  return `/${pieces.join('/')}`;
}

function reaches(program: TSESTree.Program): boolean {
  let found = false;
  walkAst(program, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const prop = node.callee.property;
      if (prop.type === 'Identifier' && (prop.name === 'query' || prop.name === 'exec')) {found = true;}
    }
  });
  return found;
}

function usesSource(program: TSESTree.Program): boolean {
  let found = false;
  walkAst(program, (node) => {
    if (node.type === 'Identifier' && (node.name === 'request' || node.name === 'params' || node.name === 'url')) {found = true;}
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && (node.callee.name === 'getQuery' || node.callee.name === 'readBody' || node.callee.name === 'getRouterParam')) {found = true;}
  });
  return found;
}

function sameRequestLocals(program: TSESTree.Program): boolean {
  const writes = new Set<string>();
  let read = false;
  walkAst(program, (node) => {
    if (node.type === 'AssignmentExpression' && node.left.type === 'MemberExpression' && node.left.property.type === 'Identifier') {
      writes.add(node.left.property.name);
    }
    if (node.type === 'CallExpression') {
      walkAst(node, (inner) => {
        if (inner.type === 'MemberExpression' && inner.property.type === 'Identifier' && writes.has(inner.property.name)) {read = true;}
      });
    }
  });
  return read && writes.size > 0;
}
