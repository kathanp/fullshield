/**
 * Phase 384. Mongo operator keys at the hook.
 * Off unless FULLSHIELD_EXPERIMENTAL_MONGOOP=1.
 * Looks at keys, not at a string search of values.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_MONGOOP';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const ALWAYS = new Set(['$where', '$function', '$accumulator']);

function keysOf(value: unknown, out: string[]): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return;
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    out.push(key);
    keysOf(record[key], out);
  }
}

export function mongoOperatorEvent(
  filter: object,
  origin: 'request' | 'constant',
  allowed: readonly string[] = [],
): boolean {
  if (!enabled() || origin === 'constant') {
    return false;
  }
  const keys: string[] = [];
  keysOf(filter, keys);
  for (const key of keys) {
    if (!key.startsWith('$')) {
      continue;
    }
    if (allowed.includes(key)) {
      continue;
    }
    if (ALWAYS.has(key) || key.startsWith('$')) {
      return true;
    }
  }
  return false;
}
