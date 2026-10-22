/**
 * Phase 374. SRI algorithm grammar.
 * Off unless FULLSHIELD_EXPERIMENTAL_SRICHECK=1.
 * Does not download the target. `--sri-from` hashes local files only.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SRICHECK';
export const SRI_FLOOR = ['sha384', 'sha512'] as const;
export const BYTES_NOT_CHECKED = 'The bytes at the URL were not checked.';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

/** Always zero. This module does not construct an HTTP client. */
export const httpClientsConstructed = 0;

export interface SriCheckFinding {
  ruleId: 'CONFIG-SRI-WEAK-001';
  severity: 'low' | 'medium';
  message: string;
}

export interface SriToken {
  algorithm: string;
  digest: string;
  wellFormed: boolean;
}

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

export function parseIntegrity(attribute: string): SriToken[] {
  const parts = attribute.trim().split(/\s+/).filter((part) => part !== '');
  if (parts.length === 0) {
    return [{ algorithm: '', digest: '', wellFormed: false }];
  }
  return parts.map((part) => {
    const dash = part.indexOf('-');
    if (dash <= 0) {
      return { algorithm: part, digest: '', wellFormed: false };
    }
    const algorithm = part.slice(0, dash).toLowerCase();
    const digest = part.slice(dash + 1);
    const wellFormed = /^[a-z0-9]+$/.test(algorithm) && digest !== '' && B64.test(digest);
    return { algorithm, digest, wellFormed };
  });
}

export function sriFindings(attribute: string): SriCheckFinding[] {
  if (!enabled()) {
    return [];
  }
  const tokens = parseIntegrity(attribute);
  const findings: SriCheckFinding[] = [];
  for (const token of tokens) {
    if (!token.wellFormed) {
      findings.push({
        ruleId: 'CONFIG-SRI-WEAK-001',
        severity: 'medium',
        message: `Malformed integrity attribute. ${BYTES_NOT_CHECKED}`,
      });
      continue;
    }
    if (!SRI_FLOOR.includes(token.algorithm as (typeof SRI_FLOOR)[number])) {
      findings.push({
        ruleId: 'CONFIG-SRI-WEAK-001',
        severity: 'low',
        message: `Integrity algorithm ${token.algorithm} is below the sha384 floor. ${BYTES_NOT_CHECKED}`,
      });
    }
  }
  return findings;
}

export function sriFromFile(attribute: string, filePath: string): SriCheckFinding[] {
  if (!enabled()) {
    return [];
  }
  if (filePath.includes('://')) {
    throw new Error('--sri-from does not take a URL');
  }
  const tokens = parseIntegrity(attribute);
  const token = tokens[0];
  if (token === undefined || !token.wellFormed) {
    return sriFindings(attribute);
  }
  const hashName = token.algorithm === 'sha512' || token.algorithm === 'sha384' || token.algorithm === 'sha256' || token.algorithm === 'sha1'
    ? token.algorithm
    : null;
  if (hashName === null) {
    return sriFindings(attribute);
  }
  const digest = createHash(hashName).update(readFileSync(filePath)).digest('base64');
  if (digest === token.digest) {
    return [];
  }
  return [
    {
      ruleId: 'CONFIG-SRI-WEAK-001',
      severity: 'medium',
      message: `Local file digest does not match the integrity attribute (${filePath}).`,
    },
  ];
}
