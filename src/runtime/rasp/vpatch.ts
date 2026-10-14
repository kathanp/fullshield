import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname } from 'node:path';

import type { SinkKind } from './types.js';

export interface VirtualPatch {
  ruleId: string;
  file?: string;
  line?: number;
  sink?: string;
  route?: string;
}

export interface VpatchFinding {
  ruleId: string;
  file?: string;
  line?: number;
  message?: string;
  route?: string;
}

function sinkFromRule(ruleId: string): string | undefined {
  const id = ruleId.toUpperCase();
  if (id.includes('SQLI') || id.includes('SQL-')) return 'sql';
  if (id.includes('CMDI') || id.includes('SHELL')) return 'shell';
  if (id.includes('PATH')) return 'path';
  if (id.includes('NOSQL')) return 'nosql';
  if (id.includes('SSRF')) return 'ssrf';
  if (id.includes('PROTO')) return 'proto';
  return undefined;
}

function routeFromFinding(f: VpatchFinding): string | undefined {
  if (typeof f.route === 'string' && f.route.startsWith('/')) return f.route;
  const fromMsg = (f.message ?? '').match(/\/[A-Za-z0-9._/-]+/);
  if (fromMsg) return fromMsg[0];
  if (f.file) {
    const base = basename(f.file, extname(f.file));
    if (base && base !== 'index') return `/${base}`;
  }
  return undefined;
}

export function findingsToVpatches(findings: VpatchFinding[]): VirtualPatch[] {
  return findings.map((f) => ({
    ruleId: f.ruleId,
    file: f.file,
    line: f.line,
    sink: sinkFromRule(f.ruleId),
    route: routeFromFinding(f),
  }));
}

export function emitVirtualPatches(findings: VpatchFinding[], outPath: string): VirtualPatch[] {
  const patches = findingsToVpatches(findings);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify({ patches }, null, 2)}\n`, 'utf8');
  return patches;
}

export function loadVirtualPatches(path: string): VirtualPatch[] {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as { patches?: VirtualPatch[] } | VirtualPatch[];
  return Array.isArray(raw) ? raw : (raw.patches ?? []);
}

export function patchForcesBlock(patches: readonly VirtualPatch[], route: string, kind: SinkKind): boolean {
  return patches.some((p) => {
    const routeHit = p.route === undefined || p.route === route;
    const sinkHit = p.sink === undefined || p.sink === kind;
    return routeHit && sinkHit;
  });
}
