import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p354.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 354', () => {
  it('returns the original text when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.foldSource('String.fromCharCode(99, 117, 114, 108)').text).toContain('fromCharCode');
  });

  it('folds a char-code literal and stops at eval', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.foldSource('String.fromCharCode(99, 117, 114, 108)').text).toContain('curl');
    expect(phase.foldSource('eval(payload)').events).toContain('fold stopped at eval');
  });
});
