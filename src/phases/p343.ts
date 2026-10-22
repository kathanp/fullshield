/**
 * Phase 343. Encrypted secret recognition.
 * Off unless FULLSHIELD_EXPERIMENTAL_ENCRYPTED=1.
 * Encrypted spans are not passed to entropy. The phase does not decrypt.
 */

import { entropyReject } from './p333.js';
import { matchGrammar, type SecretFormat } from './p332.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ENCRYPTED';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface EncryptedFinding {
  ruleId: 'SECRETS-FORMAT-001' | 'SECRETS-ENTROPY-001';
  severity: 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  witness: string;
}

const SOPS_META = ['sops:', 'unencrypted_suffix:', 'lastmodified:'];

export function encryptedSpans(text: string): { start: number; end: number }[] {
  if (text.startsWith('\0GITCRYPT\0') || text.startsWith('-----BEGIN AGE ENCRYPTED FILE-----')) {
    return [{ start: 0, end: text.length }];
  }
  const spans: { start: number; end: number }[] = [];
  if (!SOPS_META.some((key) => text.includes(key))) {
    return spans;
  }
  let from = 0;
  while (from < text.length) {
    const start = text.indexOf('ENC[', from);
    if (start < 0) {
      break;
    }
    const end = text.indexOf(']', start);
    if (end < 0) {
      break;
    }
    spans.push({ start, end: end + 1 });
    from = end + 1;
  }
  const ageStart = text.indexOf('-----BEGIN AGE ENCRYPTED FILE-----');
  const ageEnd = text.indexOf('-----END AGE ENCRYPTED FILE-----');
  if (ageStart >= 0 && ageEnd > ageStart) {
    spans.push({ start: ageStart, end: ageEnd + '-----END AGE ENCRYPTED FILE-----'.length });
  }
  return spans;
}

function complement(text: string, spans: readonly { start: number; end: number }[]): string {
  let out = '';
  let cursor = 0;
  const ordered = [...spans].sort((a, b) => a.start - b.start);
  for (const span of ordered) {
    out += text.slice(cursor, span.start);
    cursor = span.end;
  }
  out += text.slice(cursor);
  return out;
}

export function scanEncrypted(file: string, text: string, formats: readonly SecretFormat[]): EncryptedFinding[] {
  if (!enabled()) {
    return [];
  }
  const visible = complement(text, encryptedSpans(text));
  const findings: EncryptedFinding[] = [];
  const matched = matchGrammar(visible, formats);
  if (matched !== undefined) {
    findings.push({
      ruleId: 'SECRETS-FORMAT-001',
      severity: 'high',
      file,
      line: 1,
      message: `Text outside an encrypted span matches format ${matched.id}.`,
      witness: matched.id,
    });
  }
  for (const token of visible.split(/\s+/)) {
    if (token.length < 16 || entropyReject({ span: token, file, line: 1 }) !== undefined) {
      continue;
    }
    if (matchGrammar(token, formats) !== undefined) {
      continue;
    }
    findings.push({
      ruleId: 'SECRETS-ENTROPY-001',
      severity: 'medium',
      file,
      line: 1,
      message: 'Visible text has a high-entropy span.',
      witness: 'shannon-v2',
    });
    break;
  }
  return findings;
}
