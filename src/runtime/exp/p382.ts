/**
 * Phase 382. Runtime string labels.
 * Off unless FULLSHIELD_EXPERIMENTAL_RTAINT=1.
 * Labels stay on primitive strings so typeof stays "string".
 * An object box would change typeof and is not installed.
 * Events store label names and the sink id. No request body.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_RTAINT';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const labels = new Map<string, Set<string>>();
let unboxed = 0;
let serial = 0;

function keyFor(token: number, value: string): string {
  return `${token}:${value}`;
}

const tokens = new Map<string, number>();

export function resetLabels(): void {
  labels.clear();
  tokens.clear();
  unboxed = 0;
  serial = 0;
}

export function unboxCount(): number {
  return unboxed;
}

/** Mark a source string. Returns the same primitive. */
export function labelSource(value: string, label: string): string {
  if (!enabled()) {
    return value;
  }
  const token = ++serial;
  tokens.set(value, token);
  const set = new Set<string>([label]);
  labels.set(keyFor(token, value), set);
  return value;
}

/** Catalog transfer: concatenation. */
export function catalogConcat(parts: readonly string[]): string {
  const result = parts.join('');
  if (!enabled()) {
    return result;
  }
  const merged = new Set<string>();
  for (const part of parts) {
    const token = tokens.get(part);
    if (token === undefined) {
      continue;
    }
    const set = labels.get(keyFor(token, part));
    if (set !== undefined) {
      for (const label of set) {
        merged.add(label);
      }
    }
  }
  if (merged.size > 0) {
    const token = ++serial;
    tokens.set(result, token);
    labels.set(keyFor(token, result), merged);
  }
  return result;
}

/** An uncatalogued helper drops the label and increments the unbox counter. */
export function throughUncatalogued(value: string, helper: (input: string) => string): string {
  if (!enabled()) {
    return helper(value);
  }
  const token = tokens.get(value);
  if (token !== undefined) {
    labels.delete(keyFor(token, value));
    tokens.delete(value);
    unboxed += 1;
  }
  return helper(value);
}

export interface LabelEvent {
  labels: string[];
  sink: string;
}

export function checkSink(sink: string, value: string, block: boolean): { blocked: boolean; event: LabelEvent | null } {
  if (!enabled()) {
    return { blocked: false, event: null };
  }
  const token = tokens.get(value);
  const set = token === undefined ? undefined : labels.get(keyFor(token, value));
  if (set === undefined || !set.has('request')) {
    return { blocked: false, event: null };
  }
  const event: LabelEvent = { labels: [...set], sink };
  return { blocked: block, event };
}
