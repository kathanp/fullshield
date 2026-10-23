/**
 * Phase 341. Fingerprint allowlist.
 * Off unless FULLSHIELD_EXPERIMENTAL_SECRETALLOW=1.
 * Flag off: the allow file is not read. A raw secret is FS-E341.
 */

import { matchGrammar, type SecretFormat } from './p332.js';
import type { FingerprintFinding } from './p340.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRETALLOW';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

class AllowlistError extends Error {
  readonly code = 'FS-E341';
  constructor(message: string) {
    super(message);
    this.name = 'AllowlistError';
  }
}

export interface AllowEntry {
  fingerprint: string;
  prefix: string;
  suffix: string;
  until?: string;
  reason: string;
  ruleId: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function collectStrings(value: unknown, into: string[]): void {
  if (typeof value === 'string') {
    into.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectStrings(item, into);
    }
    return;
  }
  if (!isRecord(value)) {
    return;
  }
  for (const item of Object.values(value)) {
    collectStrings(item, into);
  }
}

function loadAllowlist(text: string, formats: readonly SecretFormat[], knownRules: readonly string[]): AllowEntry[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new AllowlistError('FS-E341 allow file is not JSON');
  }
  const strings: string[] = [];
  collectStrings(parsed, strings);
  for (const value of strings) {
    if (matchGrammar(value, formats) !== undefined) {
      throw new AllowlistError('FS-E341 allow file contains a secret');
    }
  }
  if (!isRecord(parsed) || !Array.isArray(parsed.entries)) {
    throw new AllowlistError('FS-E341 allow file is missing entries');
  }
  const entries: AllowEntry[] = [];
  for (const entry of parsed.entries) {
    if (!isRecord(entry) || typeof entry.fingerprint !== 'string' || typeof entry.prefix !== 'string' || typeof entry.suffix !== 'string' || typeof entry.reason !== 'string' || typeof entry.ruleId !== 'string') {
      throw new AllowlistError('FS-E341 allow entry is incomplete');
    }
    if (!knownRules.includes(entry.ruleId)) {
      throw new AllowlistError(`FS-E341 unknown rule ${entry.ruleId}`);
    }
    entries.push({
      fingerprint: entry.fingerprint,
      prefix: entry.prefix,
      suffix: entry.suffix,
      until: typeof entry.until === 'string' ? entry.until : undefined,
      reason: entry.reason,
      ruleId: entry.ruleId,
    });
  }
  return entries;
}

export function applyAllowFile(
  findings: readonly FingerprintFinding[],
  read: () => string,
  formats: readonly SecretFormat[],
  knownRules: readonly string[],
  now: string,
): FingerprintFinding[] {
  if (!enabled()) {
    return findings as FingerprintFinding[];
  }
  const entries = loadAllowlist(read(), formats, knownRules);
  return findings.filter((finding) => {
    const hit = entries.find((entry) => entry.fingerprint === finding.fingerprint && entry.prefix === finding.prefix && entry.suffix === finding.suffix && entry.ruleId === finding.ruleId);
    if (hit === undefined) {
      return true;
    }
    return hit.until !== undefined && hit.until < now;
  });
}
