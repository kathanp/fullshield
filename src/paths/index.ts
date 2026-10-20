import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { severityRank, type Finding } from '../core/finding.js';
import { attachParents } from '../modules/sast/ast.js';
import type { AstNode } from '../modules/sast/types.js';
import { dependencyPaths, secretPaths, sinkPaths } from './chains.js';
import { inventoryRoutes } from './routes.js';
import type { AttackPath } from './types.js';

export type { AttackPath, AttackPathEntry, AttackPathStep } from './types.js';

export const PATHS_FLAG = 'FULLSHIELD_EXPERIMENTAL_PATHS';

const SOURCE_EXT = /\.[cm]?[jt]sx?$/;
const MAX_BYTES = 1024 * 1024;

export function pathsEnabled(): boolean {
  return process.env[PATHS_FLAG] === '1';
}

export async function buildAttackPaths(
  findings: readonly Finding[],
  sources: ReadonlyMap<string, string>,
): Promise<AttackPath[]> {
  const asts = await parseSources(sources);
  const routes = inventoryRoutes(asts);
  const paths = [
    ...sinkPaths(findings, routes),
    ...dependencyPaths(findings, routes, asts),
    ...secretPaths(findings, routes, asts),
  ];
  return sortPaths(dedupePaths(paths), findings);
}

export async function buildAttackPathsFromFiles(
  findings: readonly Finding[],
  cwd: string,
  files: readonly string[],
): Promise<AttackPath[]> {
  const sources = new Map<string, string>();
  for (const file of files) {
    if (!SOURCE_EXT.test(file)) continue;
    const text = await readSource(join(cwd, file));
    if (text !== undefined) sources.set(file, text);
  }
  return buildAttackPaths(findings, sources);
}

async function readSource(file: string): Promise<string | undefined> {
  try {
    const text = await readFile(file, 'utf8');
    if (text.length > MAX_BYTES || text.includes('\0')) return undefined;
    return text;
  } catch {
    return undefined;
  }
}

async function parseSources(sources: ReadonlyMap<string, string>): Promise<Map<string, AstNode>> {
  const { parseSource } = await import('../modules/sast/engine.js');
  const asts = new Map<string, AstNode>();
  for (const file of [...sources.keys()].sort()) {
    const text = sources.get(file);
    if (text === undefined || !SOURCE_EXT.test(file)) continue;
    try {
      const ast = await parseSource(text);
      attachParents(ast);
      asts.set(file, ast);
    } catch {
      // A file that does not parse contributes no route.
    }
  }
  return asts;
}

function dedupePaths(paths: readonly AttackPath[]): AttackPath[] {
  const seen = new Set<string>();
  const out: AttackPath[] = [];
  for (const path of paths) {
    const steps = path.steps.map((step) => `${step.file}:${step.line ?? ''}`).join(',');
    const key = `${path.kind}|${path.entry?.method ?? ''}|${path.entry?.path ?? ''}|${path.sink.id}|${steps}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(path);
  }
  return out;
}

export function sortPaths(paths: readonly AttackPath[], findings: readonly Finding[]): AttackPath[] {
  const byId = new Map(findings.map((finding) => [finding.id, finding]));
  const anyPriority = findings.some((finding) => priorityOf(finding) !== undefined);
  return [...paths].sort((a, b) => comparePaths(a, b, byId, anyPriority));
}

function comparePaths(
  a: AttackPath,
  b: AttackPath,
  byId: ReadonlyMap<string, Finding>,
  anyPriority: boolean,
): number {
  if (anyPriority) {
    const delta = maxPriority(b, byId) - maxPriority(a, byId);
    if (delta !== 0) return delta;
  }
  const severity = maxSeverity(b, byId) - maxSeverity(a, byId);
  if (severity !== 0) return severity;
  const file = (a.sink.file ?? '').localeCompare(b.sink.file ?? '');
  if (file !== 0) return file;
  const path = (a.entry?.path ?? '').localeCompare(b.entry?.path ?? '');
  if (path !== 0) return path;
  return a.sink.ruleId.localeCompare(b.sink.ruleId) || a.sink.id.localeCompare(b.sink.id);
}

function maxPriority(path: AttackPath, byId: ReadonlyMap<string, Finding>): number {
  let best = -1;
  for (const id of path.findingIds) {
    const finding = byId.get(id);
    const value = finding === undefined ? undefined : priorityOf(finding);
    if (value !== undefined && value > best) best = value;
  }
  return best;
}

function maxSeverity(path: AttackPath, byId: ReadonlyMap<string, Finding>): number {
  let best = severityRank(path.sink.severity);
  for (const id of path.findingIds) {
    const finding = byId.get(id);
    if (finding !== undefined) best = Math.max(best, severityRank(finding.severity));
  }
  return best;
}

function priorityOf(finding: Finding): number | undefined {
  const value = (finding as Finding & { priority?: unknown }).priority;
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}
