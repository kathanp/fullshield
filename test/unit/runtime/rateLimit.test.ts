import { describe, expect, it } from 'vitest';

import { createRateLimiter } from '../../../src/runtime/rateLimit.js';

describe('createRateLimiter window and array reuse', () => {
  it('treats a hit exactly at the window edge as expired and allows a refill', () => {
    const limiter = createRateLimiter({ windowMs: 1_000, max: 1 });
    expect(limiter.allow('ip:/login', 0)).toBe(true);
    expect(limiter.allow('ip:/login', 999)).toBe(false);
    expect(limiter.allow('ip:/login', 1_000)).toBe(true);
    expect(limiter.allow('ip:/login', 1_000)).toBe(false);
  });

  it('empties the timestamp array when every hit expires, then refills in the new window', () => {
    const limiter = createRateLimiter({ windowMs: 1_000, max: 2 });
    expect(limiter.allow('k', 0)).toBe(true);
    expect(limiter.allow('k', 100)).toBe(true);
    expect(limiter.allow('k', 200)).toBe(false);
    expect(limiter.allow('k', 1_100)).toBe(true);
    expect(limiter.allow('k', 1_150)).toBe(true);
    expect(limiter.allow('k', 1_200)).toBe(false);
    expect(limiter.size).toBe(1);
  });
});
