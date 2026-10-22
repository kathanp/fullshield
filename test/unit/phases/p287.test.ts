import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p287.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 287', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeStored('db.query("1");').findings).toEqual([]);
  });

  it('does not report a literal query as stored input', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeStored('db.query("select 1");').findings).toEqual([]);
  });
});
