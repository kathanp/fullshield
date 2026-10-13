export type AttackKind = 'sqli' | 'xss' | 'path';

const SQLI =
  /('\s*or\s+'?1'?\s*='?1)|union\s+select|;\s*drop\s+table|;\s*delete\s+from/i;
const XSS = /<\s*script\b|javascript:\s*|onerror\s*=/i;
const PATH = /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\)/i;

/** Flatten query/body/params into strings. Never returns the raw object. */
export function flattenValues(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 8 || out.length > 200) return out;
  if (typeof value === 'string') {
    out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) flattenValues(item, out, depth + 1);
    return out;
  }
  if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value as Record<string, unknown>)) {
      flattenValues(item, out, depth + 1);
    }
  }
  return out;
}

export function detectAttack(text: string): AttackKind | undefined {
  if (PATH.test(text)) return 'path';
  if (XSS.test(text)) return 'xss';
  if (SQLI.test(text)) return 'sqli';
  return undefined;
}

export function inspectValues(values: readonly string[]): AttackKind | undefined {
  for (const value of values) {
    const hit = detectAttack(value);
    if (hit !== undefined) return hit;
  }
  return undefined;
}
