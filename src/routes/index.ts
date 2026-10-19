import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { calleeName, literalString, propName, walk } from '../modules/sast/ast.js';
import { parseSource } from '../modules/sast/engine.js';
import type { AstNode } from '../modules/sast/types.js';

const METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);
const AUTH = /auth|login|requireUser|requireAuth|authenticate|authorize|passport/i;
const SINK: Record<string, string> = {
  query: 'sql',
  execute: 'sql',
  exec: 'shell',
  execSync: 'shell',
  spawn: 'shell',
  spawnSync: 'shell',
  readFile: 'path',
  readFileSync: 'path',
  writeFile: 'path',
  writeFileSync: 'path',
  fetch: 'ssrf',
  request: 'ssrf',
  eval: 'eval',
};

export interface RouteRow {
  method: string;
  path: string;
  auth: string;
  validation: string;
  sinks: string[];
}

export function routesEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_ROUTES === '1';
}

/** Local only. No network. Does not detect IDOR or missing ownership checks. */
export async function routeMap(cwd: string, files: readonly string[]): Promise<RouteRow[]> {
  const rows: RouteRow[] = [];
  for (const rel of files) {
    if (!/\.[cm]?[jt]sx?$/.test(rel)) continue;
    let source: string;
    try {
      source = await readFile(join(cwd, rel), 'utf8');
    } catch {
      continue;
    }
    let ast: AstNode;
    try {
      ast = await parseSource(source);
    } catch {
      continue;
    }
    walk(ast, (node) => {
      if (node.type !== 'CallExpression') return;
      const method = calleeName(node);
      if (method === undefined || !METHODS.has(method)) return;
      const obj = node.callee.type === 'MemberExpression' ? node.callee.object : undefined;
      if (obj?.type !== 'Identifier' || !/^(app|router)$/i.test(obj.name)) return;
      const path = literalString(node.arguments[0]) ?? '(dynamic)';
      const names = node.arguments.flatMap(argNames);
      const auth = names.find((name) => AUTH.test(name)) ?? '';
      const validation = names.find((name) => /valid|schema|zod|joi/i.test(name)) ?? '';
      const handler = [...node.arguments].reverse().find((arg) => arg.type.includes('Function'));
      const sinks = new Set<string>();
      if (handler !== undefined) {
        walk(handler, (child) => {
          if (child.type !== 'CallExpression') return;
          const sink = calleeName(child);
          if (sink !== undefined && SINK[sink] !== undefined) sinks.add(SINK[sink]);
        });
      }
      rows.push({ method: method.toUpperCase(), path, auth, validation, sinks: [...sinks].sort() });
    });
  }
  return rows.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
}

function argNames(node: AstNode): string[] {
  if (node.type === 'Identifier') return [node.name];
  if (node.type === 'MemberExpression') {
    const prop = propName(node);
    return prop !== undefined ? [prop] : [];
  }
  return [];
}

export function renderRouteTable(rows: readonly RouteRow[]): string {
  const header = 'method\tpath\tauth\tvalidation\tsinks';
  const lines = rows.map(
    (row) => `${row.method}\t${row.path}\t${row.auth || '-'}\t${row.validation || '-'}\t${row.sinks.join(',') || '-'}`,
  );
  return [header, ...lines, ''].join('\n');
}
