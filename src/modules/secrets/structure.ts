/**
 * Phase 82. Offline structure checks. Flag off leaves findings unchanged.
 * GitHub token checksum: https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
 * The last 6 characters are a CRC-32 (IEEE) of the preceding body, base62-encoded.
 * npm token checksums are not applied: the public format doc does not define one.
 */

import type { Confidence, Finding } from '../../core/finding.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRET_CHECK';
const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const AWS_EXAMPLE = 'AKIAIOSFODNN7EXAMPLE';

export function secretCheckEnabled(): boolean {
  return process.env[FLAG] === '1';
}

function crc32(text: string): number {
  let crc = 0xffffffff;
  for (let i = 0; i < text.length; i += 1) {
    crc ^= text.charCodeAt(i);
    for (let bit = 0; bit < 8; bit += 1) {
      const mask = -(crc & 1);
      crc = (crc >>> 1) ^ (0xedb88320 & mask);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function encodeBase62(value: number): string {
  let rest = value >>> 0;
  let out = '';
  for (let i = 0; i < 6; i += 1) {
    out = BASE62[rest % 62] + out;
    rest = Math.floor(rest / 62);
  }
  return out;
}

/** Build a `ghp_` token whose checksum matches the documented algorithm. Tests only. */
export function githubTokenWithChecksum(body30: string): string {
  if (!/^[A-Za-z0-9]{30}$/.test(body30)) {
    throw new Error('github token body must be 30 alphanumeric characters');
  }
  return `ghp_${body30}${encodeBase62(crc32(body30))}`;
}

export function githubChecksumOk(token: string): boolean | undefined {
  const prefixed = /^(?:ghp|gho|ghu|ghs|ghr)_(.+)$/.exec(token);
  const fine = /^github_pat_(.+)$/.exec(token);
  const body = prefixed?.[1] ?? fine?.[1];
  if (body === undefined || body.length < 7) return undefined;
  const payload = body.slice(0, -6);
  const check = body.slice(-6);
  return encodeBase62(crc32(payload)) === check;
}

function lower(confidence: Confidence): Confidence {
  if (confidence === 'high') return 'medium';
  if (confidence === 'medium') return 'low';
  return 'low';
}

function isPlaceholder(secret: string): boolean {
  if (secret === AWS_EXAMPLE) return true;
  if (/^(.)\1+$/.test(secret)) return true;
  if (secret.length >= 4 && [...secret].every((char, index) => index === 0 || char.charCodeAt(0) === secret.charCodeAt(index - 1) + 1)) {
    return true;
  }
  return /example|sample|dummy|changeme|your_|xxxx|<[^>\n]+>|\$\{[^}\n]+\}/i.test(secret);
}

function isTestPath(file: string | undefined): boolean {
  if (file === undefined) return false;
  const path = file.replaceAll('\\', '/');
  return (
    path.includes('/test/') ||
    path.startsWith('test/') ||
    path.includes('/__tests__/') ||
    path.includes('/fixtures/') ||
    path.endsWith('.test.js') ||
    path.endsWith('.test.ts') ||
    path.endsWith('.spec.js') ||
    path.endsWith('.spec.ts') ||
    path.endsWith('.example') ||
    path.endsWith('.sample')
  );
}

/** Adjust one secret finding. No-op when the flag is off or nothing matches. */
export function applySecretStructure(finding: Finding, secret: string | undefined, file?: string): Finding {
  if (!secretCheckEnabled()) return finding;
  let next = finding;
  const value = secret ?? '';
  if (finding.ruleId === 'SECRET-GITHUB-001' && value.length > 0) {
    const ok = githubChecksumOk(value);
    if (ok === false) {
      next = { ...next, confidence: 'low', secretCheck: 'checksum-failed' };
    }
  }
  if (value.length > 0 && isPlaceholder(value)) {
    next = { ...next, confidence: 'low', secretCheck: 'placeholder' };
  }
  const path = file ?? finding.file;
  if (isTestPath(path)) {
    next = { ...next, confidence: lower(next.confidence), context: 'test' };
  }
  return next;
}
