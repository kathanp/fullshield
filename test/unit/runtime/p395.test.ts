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
    expect(() => canaryDecision(Number.NaN, 'req-1')).toThrow(FsError);
    expect(() => canaryDecision(-0.1, 'req-1')).toThrow(FsError);
  });

  it('blocks some request ids and monitors others at the same fraction', () => {
    process.env[FLAG] = '1';
    try {
      let blocked = 0;
      let monitored = 0;
      for (let i = 0; i < 64; i += 1) {
        if (canaryDecision(0.5, `req-${i}`) === 'block') {blocked += 1;}
        else {monitored += 1;}
      }
      expect(blocked).toBeGreaterThan(0);
      expect(monitored).toBeGreaterThan(0);
    } finally {
      delete process.env[FLAG];
    }
  });
});
