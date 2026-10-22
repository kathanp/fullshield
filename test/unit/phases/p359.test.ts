import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p359.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 359', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    const time = Object.fromEntries(Array.from({ length: 11 }, (_unused, index) => [String(index), '2026-01-30T00:00:00.000Z']));
    expect(phase.cadence('left', time, new Date('2026-02-01T00:00:00.000Z'))).toEqual([]);
  });

  it('reports a burst and ignores a steady history', () => {
    process.env[phase.FLAG] = '1';
    const now = new Date('2026-02-01T00:00:00.000Z');
    const burst = Object.fromEntries(Array.from({ length: 11 }, (_unused, index) => ['1.0.' + String(index), '2026-01-30T00:00:00.000Z']));
    expect(phase.cadence('left', burst, now)[0]?.shape).toBe(phase.BURST);
    expect(phase.cadence('left', { '1.0.0': '2020-01-01T00:00:00.000Z' }, now)).toEqual([]);
    const gap = phase.cadence('left', { '1.0.0': '2024-01-01T00:00:00.000Z', '1.0.1': '2026-01-30T00:00:00.000Z' }, now);
    expect(gap[0]?.shape).toBe(phase.GAP);
    expect(gap[0]?.message).not.toContain('malicious');
  });
});
