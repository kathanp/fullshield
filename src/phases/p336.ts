/**
 * Phase 336. Secrets in test snapshots.
 * Off unless FULLSHIELD_EXPERIMENTAL_SECRETSNAP=1.
 * Prefix-only matches drop to info. Checksummed matches keep high.
 */

import { matchGrammar, type SecretFormat } from './p332.js';
import { secretEdges, secretFingerprint } from './p340.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRETSNAP';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SnapFinding {
  ruleId: 'SECRETS-FORMAT-001';
  severity: 'info' | 'high';
  file: string;
  line: number;
  message: string;
  fingerprint: string;
  prefix: string;
  suffix: string;
}

export interface AllowHit {
  fingerprint: string;
  prefix: string;
  suffix: string;
  ruleId: string;
}

function snapshotFile(file: string): boolean {
  const path = file.replaceAll('\\', '/');
  return path.endsWith('.snap') || path.includes('toMatchInlineSnapshot');
}

function syntheticAllow(path: string, synthetic: boolean): boolean {
  const normalized = path.replaceAll('\\', '/');
  return synthetic && (normalized.startsWith('test/') || normalized.includes('/test/') || normalized.startsWith('examples/') || normalized.includes('/examples/'));
}

export function snapshotFindings(file: string, text: string, formats: readonly SecretFormat[], allow: readonly AllowHit[] = []): SnapFinding[] {
  if (!enabled() || !snapshotFile(file)) {
    return [];
  }
  const matched = matchGrammar(text, formats);
  if (matched === undefined || syntheticAllow(file, matched.synthetic)) {
    return [];
  }
  const token = formats.flatMap((format) => format.synthetic.map((example) => example.value)).find((value) => text.includes(value)) ?? '';
  const edges = secretEdges(token);
  const fingerprint = secretFingerprint(token, 'SECRETS-FORMAT-001');
  if (allow.some((entry) => entry.fingerprint === fingerprint && entry.prefix === edges.prefix && entry.suffix === edges.suffix && entry.ruleId === 'SECRETS-FORMAT-001')) {
    return [];
  }
  return [
    {
      ruleId: 'SECRETS-FORMAT-001',
      severity: matched.checksum ? 'high' : 'info',
      file,
      line: 1,
      message: matched.checksum ? `Snapshot keeps format ${matched.id} severity.` : `Snapshot prefix match for format ${matched.id} is info.`,
      fingerprint,
      prefix: edges.prefix,
      suffix: edges.suffix,
    },
  ];
}
