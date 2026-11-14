import { readFile } from 'node:fs/promises';
import { isAbsolute, join, relative } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';

import { routesIn, type Endpoint } from './routes.js';
import { parseSpec, type SpecOp } from './spec.js';

export const CONTRACT_FLAG = 'FULLSHIELD_EXPERIMENTAL_CONTRACT';

export interface ContractFile {
  file: string;
  source: string;
}

const SOURCE = /\.[cm]?[jt]sx?$/;

function wanted(file: string): boolean {
  const name = file.split('\\').join('/');
  return SOURCE.test(name) || /(^|\/)openapi\.(yaml|json)$/.test(name);
}

function specFile(files: readonly ContractFile[]): ContractFile | undefined {
  const specs = files.filter((file) => /(^|\/)openapi\.(yaml|json)$/.test(file.file.split('\\').join('/')));
  specs.sort((a, b) => a.file.length - b.file.length || a.file.localeCompare(b.file));
  return specs[0];
}

function finding(ruleId: string, message: string, file: string, line: number): Finding {
  const title = ruleId === 'CONTRACT-SPEC-001' ? 'OpenAPI path has no route' : 'Route has no OpenAPI path';
  return {
    id: makeFindingId(ruleId, file, message),
    ruleId,
    module: 'contract',
    title,
    severity: 'medium',
    confidence: 'medium',
    cwe: 'CWE-1059',
    file,
    line,
    message,
    remediation: 'Make the OpenAPI path and method match a registered route, or remove the side that should not exist. Query parameters and response bodies are not compared.',
  };
}

function specMissing(op: SpecOp, routes: readonly Endpoint[], file: string, found: Finding[]): void {
  const covered = routes.some((route) => route.path === op.path && (route.method === op.method || route.method === 'ALL'));
  if (!covered) {found.push(finding('CONTRACT-SPEC-001', `OpenAPI ${op.method} ${op.path} has no registered route.`, file, op.line));}
}

function routeMissing(route: Endpoint, ops: readonly SpecOp[], found: Finding[]): void {
  const covered = route.method === 'ALL'
    ? ops.some((op) => op.path === route.path)
    : ops.some((op) => op.path === route.path && op.method === route.method);
  if (!covered) {found.push(finding('CONTRACT-ROUTE-001', `Registered ${route.method} ${route.path} has no OpenAPI path.`, route.file, route.line));}
}

export async function scanContractSources(files: readonly ContractFile[]): Promise<Finding[]> {
  const spec = specFile(files);
  if (spec === undefined) {return [];}
  const ops = parseSpec(spec.file, spec.source);
  if (ops === undefined) {return [];}
  const routes: Endpoint[] = [];
  for (const file of files) {
    if (!SOURCE.test(file.file)) {continue;}
    routes.push(...await routesIn(file.file, file.source));
  }
  const found: Finding[] = [];
  for (const op of ops) {specMissing(op, routes, spec.file, found);}
  for (const route of routes) {routeMissing(route, ops, found);}
  const uniq = new Map<string, Finding>();
  for (const item of found) {uniq.set(`${item.ruleId}|${item.file}|${item.line}|${item.message}`, item);}
  return [...uniq.values()];
}

export const contractModule: ScanModule = {
  name: 'contract',
  async run(ctx) {
    if (process.env[CONTRACT_FLAG] !== '1') {return [];}
    const sources: ContractFile[] = [];
    for (const file of ctx.files) {
      if (!wanted(file)) {continue;}
      const abs = join(ctx.cwd, file);
      const rel = relative(ctx.cwd, abs);
      if (rel.startsWith('..') || isAbsolute(rel)) {continue;}
      sources.push({ file: file.split('\\').join('/'), source: await readFile(abs, 'utf8') });
    }
    return scanContractSources(sources);
  },
};
