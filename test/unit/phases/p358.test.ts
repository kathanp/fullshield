import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p358.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

const now = new Date('2026-02-01T00:00:00.000Z');

describe('phase 358', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.ageBucket('left', { '1.0.0': '2026-01-31T00:00:00.000Z' }, true, now)).toEqual([]);
  });

  it('buckets a young direct package and ignores an old one', () => {
    process.env[phase.FLAG] = '1';
    const young = phase.ageBucket('left', { '1.0.0': '2026-01-31T00:00:00.000Z' }, true, now);
    expect(young[0]?.bucket).toBe('younger-than-7d');
    expect(young[0]?.message).toContain('not a malware finding');
    expect(JSON.stringify(young)).not.toContain('score');
    expect(phase.ageBucket('left', { '1.0.0': '2020-01-01T00:00:00.000Z' }, true, now)).toEqual([]);
    expect(phase.ageBucket('left', { '1.0.0': '2026-01-31T00:00:00.000Z' }, false, now)).toEqual([]);
  });

  it('skips modified, ignores stamps that do not parse, and buckets thirty days', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.ageBucket('left', undefined, true, now)).toEqual([]);
    expect(phase.ageBucket('left', { modified: '2026-01-31T00:00:00.000Z', created: 'not-a-date' }, true, now)).toEqual([]);
    const month = phase.ageBucket('left', { modified: '2026-02-01T00:00:00.000Z', '1.0.0': '2026-01-10T00:00:00.000Z' }, true, now);
    expect(month[0]?.bucket).toBe('younger-than-30d');
    expect(month[0]?.versionCount).toBe(1);
  });
});
