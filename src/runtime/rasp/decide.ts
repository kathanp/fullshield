import { nosqlUserOperators } from './nosql.js';
import { pathInputEscapes } from './path.js';
import { protoPolluted } from './proto.js';
import { shellInputChangesStructure } from './shell.js';
import { sqlInputChangesStructure } from './sql.js';
import { ssrfHostFromUser } from './ssrf.js';
import { RASP_RULE, type Decision, type RaspRequestContext, type SinkKind } from './types.js';

function sinkTexts(sink: unknown): string[] {
  if (typeof sink === 'string') return [sink];
  if (typeof sink === 'number' || typeof sink === 'boolean') return [String(sink)];
  return [];
}

export function detectStructureChange(
  kind: SinkKind,
  sink: unknown,
  ctx: RaspRequestContext,
  base?: string,
): boolean {
  if (kind === 'proto') return protoPolluted(ctx);
  if (kind === 'nosql') return nosqlUserOperators(sink, ctx);
  for (const text of sinkTexts(sink)) {
    for (const input of ctx.strings) {
      if (!input) continue;
      if (kind === 'sql' && sqlInputChangesStructure(text, input)) return true;
      if (kind === 'shell' && shellInputChangesStructure(text, input)) return true;
      if (kind === 'path' && pathInputEscapes(text, input, base)) return true;
      if (kind === 'ssrf' && ssrfHostFromUser(text, input)) return true;
    }
  }
  return false;
}

export function decideSink(kind: SinkKind, sink: unknown, ctx: RaspRequestContext, base?: string): Decision {
  const hit = detectStructureChange(kind, sink, ctx, base);
  if (hit) return { block: true, ruleId: RASP_RULE[kind] };
  return { block: false };
}

export function contextForCorpusCase(c: Record<string, unknown>): RaspRequestContext {
  const kind = c.kind;
  const input = c.input;
  if (kind === 'proto' || (input !== null && typeof input === 'object')) {
    return {
      path: '/',
      ip: 'test',
      strings: [],
      objects: input !== null && typeof input === 'object' ? [input] : [],
    };
  }
  const text = typeof input === 'string' || typeof input === 'number' || typeof input === 'boolean' ? String(input) : '';
  return {
    path: '/',
    ip: 'test',
    strings: text ? [text] : [],
    objects: [],
  };
}

export interface CorpusKindScore {
  blocked: number;
  total: number;
}

export function scoreCorpusByKind(cases: Array<Record<string, unknown>>): {
  blocked: number;
  total: number;
  byKind: Record<string, CorpusKindScore>;
} {
  const byKind: Record<string, CorpusKindScore> = {};
  let blocked = 0;
  for (const c of cases) {
    const kind = typeof c.kind === 'string' ? c.kind : 'unknown';
    const ctx = contextForCorpusCase(c);
    const sink = kind === 'proto' ? null : (c.sink ?? c.input);
    const base = typeof c.base === 'string' ? c.base : undefined;
    const hit = decideSink(kind as SinkKind, sink, ctx, base).block;
    const slot = byKind[kind] ?? { blocked: 0, total: 0 };
    slot.total += 1;
    if (hit) {
      slot.blocked += 1;
      blocked += 1;
    }
    byKind[kind] = slot;
  }
  return { blocked, total: cases.length, byKind };
}

export function scoreCorpus(cases: Array<Record<string, unknown>>): { blocked: number; total: number } {
  const { blocked, total } = scoreCorpusByKind(cases);
  return { blocked, total };
}
