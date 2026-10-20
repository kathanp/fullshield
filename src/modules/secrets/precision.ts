import { crc32 } from 'node:zlib';

import type { Confidence, Finding } from '../../core/finding.js';

/** Phase 82. Off unless FULLSHIELD_EXPERIMENTAL_SECRET_CHECK=1. */
export function secretCheckEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_SECRET_CHECK === '1';
}

/**
 * GitHub token checksum, public format only:
 * https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
 * CRC-32/IEEE of the body excluding the 6-character base62 suffix.
 * npm tokens are not checked: no issuer checksum doc is cited.
 */
const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const CLASSIC = /^(?:ghp|gho|ghu|ghs|ghr)_([A-Za-z0-9]{36})$/;
const FINE = /^github_pat_([A-Za-z0-9]{22}_[A-Za-z0-9]{59})$/;
const AWS_EXAMPLE_KEY = 'AKIAIOSFODNN7EXAMPLE';
const PLACEHOLDER_WORDS = ['example', 'sample', 'dummy', 'changeme', 'your_', 'xxxx'] as const;
const TEST_DIRS = new Set(['test', '__tests__', 'fixtures']);

function base62Crc(data: string): string {
  let n = crc32(data) >>> 0;
  let out = '';
  for (let i = 0; i < 6; i += 1) {
    out = ALPHABET.charAt(n % 62) + out;
    n = Math.floor(n / 62);
  }
  return out;
}

function githubChecksum(secret: string): 'pass' | 'fail' | 'skip' {
  const body = CLASSIC.exec(secret)?.[1] ?? FINE.exec(secret)?.[1];
  if (body === undefined) {return 'skip';}
  return body.slice(-6) === base62Crc(body.slice(0, -6)) ? 'pass' : 'fail';
}

function isSequential(secret: string): boolean {
  if (secret.length < 2) {return false;}
  let up = true;
  let down = true;
  for (let i = 1; i < secret.length; i += 1) {
    const diff = secret.charCodeAt(i) - secret.charCodeAt(i - 1);
    if (diff !== 1) {up = false;}
    if (diff !== -1) {down = false;}
  }
  return up || down;
}

function isPlaceholder(secret: string): boolean {
  if (secret === AWS_EXAMPLE_KEY) {return true;}
  if (secret.length > 0 && [...secret].every((char) => char === secret[0])) {return true;}
  if (isSequential(secret)) {return true;}
  const lower = secret.toLowerCase();
  if (PLACEHOLDER_WORDS.some((word) => lower.includes(word))) {return true;}
  if (/<[^>]+>/.test(secret)) {return true;}
  if (/\$\{[^}]+\}/.test(secret)) {return true;}
  return false;
}

function isTestContext(filePath: string): boolean {
  const parts = filePath.split('\\').join('/').split('/');
  for (let i = 0; i < parts.length - 1; i += 1) {
    if (TEST_DIRS.has(parts[i] ?? '')) {return true;}
  }
  const base = parts[parts.length - 1] ?? filePath;
  if (base.includes('.test.') || base.includes('.spec.')) {return true;}
  return base.endsWith('.example') || base.endsWith('.sample');
}

function lowerConfidence(confidence: Confidence): Confidence {
  if (confidence === 'high') {return 'medium';}
  if (confidence === 'medium') {return 'low';}
  return 'low';
}

/** Annotate one finding. Does not change severity and does not drop the finding. */
export function applySecretPrecision(file: string, finding: Finding, secret: string | undefined): void {
  let confidence = finding.confidence;
  if (secret !== undefined && secret.length > 0) {
    if (githubChecksum(secret) === 'fail') {
      confidence = 'low';
      finding.secretCheck = 'checksum-failed';
    }
    if (isPlaceholder(secret)) {
      confidence = 'low';
      finding.secretCheck = 'placeholder';
    }
  }
  if (isTestContext(file)) {
    confidence = lowerConfidence(confidence);
    finding.context = 'test';
  }
  finding.confidence = confidence;
}
