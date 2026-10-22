import { describe, expect, it } from 'vitest';

import { canaryDecision, enabled, FLAG, FsError } from '../../../src/runtime/exp/p395.js';

describe('phase 395 canary', () => {
  it('does not block when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(canaryDecision(1, 'req-1')).toBe('monitor');
  });

  it('never blocks at fraction 0 and blocks the corpus at fraction 1', () => {
    process.env[FLAG] = '1';
    expect(canaryDecision(0, 'req-1')).toBe('monitor');
    expect(canaryDecision(1, 'payload')).toBe('block');
  });

  it('monitors a missing header even at fraction 1', () => {
    process.env[FLAG] = '1';
    expect(canaryDecision(1, null)).toBe('monitor');
    expect(canaryDecision(1, '')).toBe('monitor');
  });

  it('repeats the same decision for the same request id', () => {
    process.env[FLAG] = '1';
    const first = canaryDecision(0.5, 'req-stable');
    for (let i = 0; i < 20; i += 1) {
      expect(canaryDecision(0.5, 'req-stable')).toBe(first);
    }
  });

  it('rejects a fraction outside 0 to 1', () => {
    expect(() => canaryDecision(1.5, 'req-1')).toThrow(FsError);
  });
});
