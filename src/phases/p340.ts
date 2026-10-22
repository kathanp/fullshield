/**
 * Phase 340. Fingerprint dedupe.
 * Off unless FULLSHIELD_EXPERIMENTAL_SECRETFINGERPRINT=1.
 * Flag off keeps one row per location. The preimage is not stored.
 */

import { createHash } from 'node:crypto';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRETFINGERPRINT';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SecretLocation {
  file: string;
  line: number;
  secret: string;
  ruleId: string;
}

export interface FingerprintFinding {
  ruleId: string;
  fingerprint: string;
  prefix: string;
  suffix: string;
  locations: { file: string; line: number }[];
}

export function secretFingerprint(secret: string, ruleId: string): string {
  return createHash('sha256').update(secret).update('\0').update(ruleId).digest('hex');
}

export function secretEdges(secret: string): { prefix: string; suffix: string } {
  return { prefix: secret.slice(0, 4), suffix: secret.slice(-4) };
}

export function dedupeSecrets(locations: readonly SecretLocation[]): FingerprintFinding[] {
  const rows: FingerprintFinding[] = [];
  if (!enabled()) {
    for (const location of locations) {
      const edges = secretEdges(location.secret);
      rows.push({
        ruleId: location.ruleId,
        fingerprint: secretFingerprint(location.secret, location.ruleId),
        prefix: edges.prefix,
        suffix: edges.suffix,
        locations: [{ file: location.file, line: location.line }],
      });
    }
    return rows;
  }
  const groups = new Map<string, FingerprintFinding>();
  for (const location of locations) {
    const fingerprint = secretFingerprint(location.secret, location.ruleId);
    const edges = secretEdges(location.secret);
    const key = `${location.ruleId}\0${fingerprint}`;
    const existing = groups.get(key);
    if (existing === undefined) {
      groups.set(key, { ruleId: location.ruleId, fingerprint, prefix: edges.prefix, suffix: edges.suffix, locations: [{ file: location.file, line: location.line }] });
    } else {
      existing.locations.push({ file: location.file, line: location.line });
    }
  }
  for (const finding of groups.values()) {
    finding.locations.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    rows.push(finding);
  }
  rows.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
  return rows;
}

export function scannerLog(findings: readonly FingerprintFinding[]): string[] {
  return findings.map((finding) => `fingerprint ${finding.prefix} ${finding.suffix} ${finding.fingerprint}`);
}
