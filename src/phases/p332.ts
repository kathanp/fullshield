/**
 * Phase 332. Provider format registry.
 * Off unless FULLSHIELD_EXPERIMENTAL_SECRETFORMAT=1.
 * No vendor rows are shipped. A missing source fails the schema.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRETFORMAT';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SecretExample {
  value: string;
  synthetic: true;
}

export interface SecretChecksum {
  algorithm: 'sum-mod';
  mod: number;
  residue: number;
}

export interface SecretFormat {
  id: string;
  source: string;
  prefix: string;
  alphabet: string;
  length: number;
  notBeforeLength: number;
  checksum?: SecretChecksum;
  synthetic: readonly SecretExample[];
}

export interface FormatMatch {
  id: string;
  checksum: boolean;
  synthetic: boolean;
}

export function alphabetSet(spec: string): Set<string> | undefined {
  const set = new Set<string>();
  for (let index = 0; index < spec.length; index += 1) {
    const start = spec[index];
    const dash = spec[index + 1];
    const end = spec[index + 2];
    if (start !== undefined && dash === '-' && end !== undefined) {
      const from = start.codePointAt(0) ?? 0;
      const to = end.codePointAt(0) ?? 0;
      if (to < from) {
        return undefined;
      }
      for (let code = from; code <= to; code += 1) {
        set.add(String.fromCodePoint(code));
      }
      index += 2;
      continue;
    }
    if (start !== undefined) {
      set.add(start);
    }
  }
  return set;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function validateFormat(row: unknown): string[] {
  if (!isRecord(row)) {
    return ['row'];
  }
  const errors: string[] = [];
  if (typeof row.id !== 'string' || row.id.length === 0) {
    errors.push('id');
  }
  if (typeof row.source !== 'string' || row.source.trim().length === 0) {
    errors.push('source');
  }
  if (typeof row.prefix !== 'string' || typeof row.alphabet !== 'string' || alphabetSet(row.alphabet) === undefined) {
    errors.push('grammar');
  }
  if (typeof row.length !== 'number' || typeof row.notBeforeLength !== 'number') {
    errors.push('length');
  }
  if (!Array.isArray(row.synthetic) || row.synthetic.some((example) => !isRecord(example) || example.synthetic !== true || typeof example.value !== 'string')) {
    errors.push('synthetic');
  }
  return errors;
}

export function loadRegistry(rows: readonly unknown[] | undefined): { ok: boolean; reason?: string; formats: SecretFormat[] } {
  if (!enabled()) {
    return { ok: true, formats: [] };
  }
  if (rows === undefined) {
    return { ok: false, reason: 'human must supply secret format rows', formats: [] };
  }
  const formats: SecretFormat[] = [];
  for (const row of rows) {
    const errors = validateFormat(row);
    if (errors.length > 0 || !isRecord(row) || !Array.isArray(row.synthetic)) {
      return { ok: false, reason: `secret format schema failed: ${errors.join(',')}`, formats: [] };
    }
    const examples: SecretExample[] = [];
    for (const example of row.synthetic) {
      if (isRecord(example) && example.synthetic === true && typeof example.value === 'string') {
        examples.push({ value: example.value, synthetic: true });
      }
    }
    const checksum = isRecord(row.checksum) && row.checksum.algorithm === 'sum-mod' && typeof row.checksum.mod === 'number' && typeof row.checksum.residue === 'number'
      ? { algorithm: 'sum-mod' as const, mod: row.checksum.mod, residue: row.checksum.residue }
      : undefined;
    formats.push({
      id: String(row.id),
      source: String(row.source),
      prefix: String(row.prefix),
      alphabet: String(row.alphabet),
      length: Number(row.length),
      notBeforeLength: Number(row.notBeforeLength),
      checksum,
      synthetic: examples,
    });
  }
  return { ok: true, formats };
}

function checksumOk(body: string, checksum: SecretChecksum): boolean {
  let sum = 0;
  for (const char of body) {
    sum += char.codePointAt(0) ?? 0;
  }
  return sum % checksum.mod === checksum.residue;
}

export function matchGrammar(text: string, formats: readonly SecretFormat[]): FormatMatch | undefined {
  for (const format of formats) {
    const alphabet = alphabetSet(format.alphabet);
    if (alphabet === undefined) {
      continue;
    }
    let from = 0;
    while (from <= text.length) {
      const at = text.indexOf(format.prefix, from);
      if (at < 0) {
        break;
      }
      const body = text.slice(at + format.prefix.length, at + format.prefix.length + format.length);
      const token = text.slice(at, at + format.prefix.length + format.length);
      const lettersOk = body.length === format.length && [...body].every((char) => alphabet.has(char));
      if (lettersOk && token.length >= format.notBeforeLength && (format.checksum === undefined || checksumOk(body, format.checksum))) {
        return { id: format.id, checksum: format.checksum !== undefined, synthetic: format.synthetic.some((example) => example.value === token) };
      }
      from = at + format.prefix.length;
    }
  }
  return undefined;
}

export function matchSecret(text: string, formats: readonly SecretFormat[]): FormatMatch | undefined {
  if (!enabled()) {
    return undefined;
  }
  return matchGrammar(text, formats);
}

export function mergeFormatFindings<T extends { ruleId: string }>(existing: readonly T[]): readonly T[] {
  return existing;
}
