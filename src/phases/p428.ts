/**
 * Phase 428. Refactor-stable fingerprints.
 * Off unless FULLSHIELD_EXPERIMENTAL_STABLEFP=1.
 * Flag off: the baseline key stays rule id, file, and line.
 */
import { createHash } from 'node:crypto';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_STABLEFP';

const KEYWORDS = new Set(['const', 'let', 'var', 'return', 'function', 'new', 'await', 'async', 'if', 'else']);

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface FingerprintInput {
  ruleId: string;
  sinkClass: string;
  origin: string;
  file: string;
  line: number;
  witnessShape: string;
}

export function legacyBaselineKey(ruleId: string, file: string, line: number): string {
  return `${ruleId}\0${file}\0${line}`;
}

function skipString(expr: string, start: number): number {
  const quote = expr[start] ?? '';
  let i = start + 1;
  while (i < expr.length) {
    const ch = expr[i] ?? '';
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === quote) {
      return i + 1;
    }
    i += 1;
  }
  return expr.length;
}

/** Identifier normalization shared by history and baseline. Strings are left intact. */
export function normalizeIdentifiers(expr: string): string {
  let out = '';
  const map = new Map<string, string>();
  let n = 0;
  let i = 0;
  while (i < expr.length) {
    const ch = expr[i] ?? '';
    if (ch === '\'' || ch === '"' || ch === '`') {
      const end = skipString(expr, i);
      out += expr.slice(i, end);
      i = end;
      continue;
    }
    if (/[A-Za-z_$]/.test(ch)) {
      let j = i + 1;
      while (j < expr.length && /[\w$]/.test(expr[j] ?? '')) {
        j += 1;
      }
      const word = expr.slice(i, j);
      if (KEYWORDS.has(word)) {
        out += word;
      } else {
        let slot = map.get(word);
        if (slot === undefined) {
          n += 1;
          slot = `v${n}`;
          map.set(word, slot);
        }
        out += slot;
      }
      i = j;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function hash(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

export function baselineKey(input: FingerprintInput): string {
  if (!enabled()) {
    return legacyBaselineKey(input.ruleId, input.file, input.line);
  }
  const shape = normalizeIdentifiers(input.witnessShape);
  return hash([input.ruleId, input.sinkClass, input.origin, input.file, shape].join('\0'));
}
