/**
 * Phase 568. Fingerprint, confirm pass, sample cap, and block-experimental.
 * Off unless FULLSHIELD_EXPERIMENTAL_RUNTIME_GUARD=1.
 * Nothing here is posted and nothing here is a DLP product.
 */
const FLAG = 'FULLSHIELD_EXPERIMENTAL_RUNTIME_GUARD';
const CAP_BYTES = 4096;

function on(): boolean {
  return process.env[FLAG] === '1';
}

function collapse(sample: string): string {
  let out = '';
  let quote = '';
  for (const ch of sample) {
    if (quote !== '') {
      if (ch === quote) {
        out += quote + quote;
        quote = '';
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch >= '0' && ch <= '9') {
      if (!out.endsWith('0')) {out += '0';}
      continue;
    }
    out += ch;
  }
  return out;
}

function hash8(text: string): string {
  let h = 5381;
  for (let i = 0; i < text.length; i += 1) {
    h = Math.imul(h, 33) ^ text.charCodeAt(i);
  }
  return (h >>> 0).toString(16).padStart(8, '0').slice(0, 8);
}

export function sqlFingerprint(sample: string): string | undefined {
  if (!on()) {return undefined;}
  return hash8(collapse(sample));
}

export function matchingSinkLines(source: string, fingerprint: string): number[] {
  if (!on() || fingerprint === '') {return [];}
  const lines: number[] = [];
  const parts = source.split('\n');
  for (let i = 0; i < parts.length; i += 1) {
    const line = parts[i] ?? '';
    if (line.includes('.query(') || line.includes('$queryRaw')) {lines.push(i + 1);}
  }
  return lines;
}

export function confirmAllowsPass(rows: readonly { status: string }[]): boolean {
  if (!on()) {return true;}
  return rows.every((row) => row.status !== 'unconfirmed');
}

export function responseWithinCap(bytes: number): boolean {
  if (!on()) {return true;}
  if (bytes > CAP_BYTES) {return false;}
  return true;
}

export function runtimeMode(value: string | undefined): 'monitor' | 'block' {
  if (!on()) {return value === 'block' ? 'block' : 'monitor';}
  if (value === 'block-experimental') {return 'block';}
  return 'monitor';
}
