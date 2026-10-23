/**
 * Phase 395. Block-mode canary.
 * Off unless FULLSHIELD_EXPERIMENTAL_CANARY=1.
 * Decision: SHA-256 of the configured request id, first 4 bytes as a big-endian
 * uint32, block when that value / 2^32 is strictly less than the fraction.
 * Fraction 0 monitors everyone. A missing id never blocks.
 */
import { createHash } from 'node:crypto';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CANARY';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export class FsError extends Error {
  readonly code = 'FS-E' as const;
  constructor(message: string) {
    super(message);
    this.name = 'FsError';
  }
}

function assertFraction(fraction: number): void {
  if (!Number.isFinite(fraction) || fraction < 0 || fraction > 1) {
    throw new FsError('fraction must be between 0 and 1');
  }
}

export function canaryDecision(fraction: number, requestId: string | null): 'block' | 'monitor' {
  assertFraction(fraction);
  if (!enabled() || fraction === 0 || requestId === null || requestId === '') {
    return 'monitor';
  }
  if (fraction === 1) {
    return 'block';
  }
  const digest = createHash('sha256').update(requestId).digest();
  const first = digest[0] ?? 0;
  const second = digest[1] ?? 0;
  const third = digest[2] ?? 0;
  const fourth = digest[3] ?? 0;
  const value = ((first * 256 + second) * 256 + third) * 256 + fourth;
  return value / 2 ** 32 < fraction ? 'block' : 'monitor';
}
