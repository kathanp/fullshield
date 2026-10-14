import type { RaspRequestContext } from './types.js';

const DANGEROUS = new Set(['__proto__', 'constructor', 'prototype']);

function walk(value: unknown, depth: number, seen: Set<unknown>): boolean {
  if (depth > 8 || value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return false;
  seen.add(value);
  for (const key of Object.getOwnPropertyNames(value)) {
    if (DANGEROUS.has(key)) return true;
  }
  if (Array.isArray(value)) return value.some((item) => walk(item, depth + 1, seen));
  return Object.values(value as Record<string, unknown>).some((child) => walk(child, depth + 1, seen));
}

export function protoPolluted(ctx: RaspRequestContext): boolean {
  const seen = new Set<unknown>();
  return ctx.objects.some((obj) => walk(obj, 0, seen));
}
