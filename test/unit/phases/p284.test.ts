import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p284.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 284', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeRedos('const re = /a/;').findings).toEqual([]);
  });

  it('parses an atom and does not flag a single literal class', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.parsePattern('a').type).toBe('atom');
    expect(phase.analyzeRedos('const re = /a/;').findings).toEqual([]);
  });
});
