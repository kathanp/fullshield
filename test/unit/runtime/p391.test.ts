import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { createStuffing, DEFAULT_FAILURES, DEFAULT_USERNAMES, enabled, FLAG } from '../../../src/runtime/exp/p391.js';

describe('phase 391 credential stuffing', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    const record = createStuffing({ failures: 1, usernames: 1 });
    expect(record('10.0.0.1', 'a', true).status).toBe(200);
  });

  it('does not 429 under the threshold', () => {
    process.env[FLAG] = '1';
    const record = createStuffing();
    let last = record('10.0.0.1', 'ada', true);
    for (let i = 0; i < 3; i += 1) {
      last = record('10.0.0.1', `user-${i}`, true);
    }
    expect(last.status).toBe(200);
    expect(DEFAULT_FAILURES).toBeGreaterThan(3);
    expect(DEFAULT_USERNAMES).toBeGreaterThan(3);
  });

  it('returns 429 when both thresholds are crossed', () => {
    process.env[FLAG] = '1';
    const record = createStuffing({ failures: 2, usernames: 1 });
    record('10.0.0.1', 'a', true);
    record('10.0.0.1', 'b', true);
    expect(record('10.0.0.1', 'c', true)).toEqual({ status: 429, event: true });
  });

  it('does not emit this event for one username and opens no socket', () => {
    process.env[FLAG] = '1';
    const record = createStuffing({ failures: 1, usernames: 2 });
    let last = { status: 200 as 200 | 429, event: false };
    for (let i = 0; i < 6; i += 1) {
      last = record('10.0.0.1', 'ada', true);
    }
    expect(last.event).toBe(false);
    const source = readFileSync(new URL('../../../src/runtime/exp/p391.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:net');
    expect(source).not.toContain('node:fs');
  });
});
