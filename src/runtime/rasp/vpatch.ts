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

export function sinkFromRule(ruleId: string): string | undefined {
  const id = ruleId.toUpperCase();
  if (id.includes('SQLI') || id.includes('SQL-')) {return 'sql';}
  if (id.includes('CMDI') || id.includes('SHELL')) {return 'shell';}
  if (id.includes('PATH')) {return 'path';}
  if (id.includes('NOSQL')) {return 'nosql';}
  if (id.includes('SSRF')) {return 'ssrf';}
  if (id.includes('PROTO')) {return 'proto';}
  return undefined;
}

export function routeFromFinding(f: VpatchFinding): string | undefined {
  if (typeof f.route === 'string' && f.route.startsWith('/')) {return f.route;}
  const fromMsg = (f.message ?? '').match(/\/[A-Za-z0-9._/-]+/);
  if (fromMsg) {return fromMsg[0];}
  if (f.file) {
    const lastSlash = Math.max(f.file.lastIndexOf('/'), f.file.lastIndexOf('\\'));
    const baseWithExt = lastSlash >= 0 ? f.file.slice(lastSlash + 1) : f.file;
    const dot = baseWithExt.lastIndexOf('.');
    const base = dot > 0 ? baseWithExt.slice(0, dot) : baseWithExt;
    if (base && base !== 'index') {return `/${base}`;}
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

export function patchForcesBlock(patches: readonly VirtualPatch[], route: string, kind: SinkKind): boolean {
  return patches.some((p) => {
    const routeHit = p.route === undefined || p.route === route;
    const sinkHit = p.sink === undefined || p.sink === kind;
    return routeHit && sinkHit;
  });
}
