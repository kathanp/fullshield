import type { RaspRequestContext } from './types.js';

function isOperatorObject(value: unknown): boolean {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.keys(value).some((k) => k.startsWith('$'));
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  const ak = Object.keys(a);
  const bk = Object.keys(b);
  if (ak.length !== bk.length) return false;
  return ak.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

function collect(value: unknown, out: unknown[], depth: number): void {
  if (depth > 8 || value === null || typeof value !== 'object') return;
  out.push(value);
  if (Array.isArray(value)) {
    for (const item of value) collect(item, out, depth + 1);
    return;
  }
  for (const child of Object.values(value as Record<string, unknown>)) collect(child, out, depth + 1);
}

export function nosqlUserOperators(sink: unknown, ctx: RaspRequestContext): boolean {
  const userObjects: unknown[] = [];
  for (const obj of ctx.objects) collect(obj, userObjects, 0);
  const userOps = userObjects.filter(isOperatorObject);
  if (userOps.length === 0) return false;

  const seen = new Set<unknown>();
  const walk = (value: unknown, depth: number): boolean => {
    if (depth > 8 || value === null || typeof value !== 'object') return false;
    if (seen.has(value)) return false;
    seen.add(value);
    if (isOperatorObject(value) && userOps.some((u) => u === value || deepEqual(u, value))) {
      return true;
    }
    if (Array.isArray(value)) return value.some((item) => walk(item, depth + 1));
    return Object.values(value as Record<string, unknown>).some((child) => walk(child, depth + 1));
  };
  return walk(sink, 0);
}
