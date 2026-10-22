import { afterEach, describe, expect, it } from 'vitest';

import { dispositionOf, enabled, FLAG, validateDispositionDocument } from '../../../src/phases/p422.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 422 fix disposition', () => {
  it('returns no disposition when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(dispositionOf({ refused: false, witnessFailed: true, holeClass: 'sql-value' })).toEqual({});
  });

  it('marks an auto-apply hole safe when the witness failed', () => {
    process.env[FLAG] = '1';
    expect(dispositionOf({ refused: false, witnessFailed: true, holeClass: 'sql-value' })).toEqual({
      disposition: 'safe',
    });
    expect(validateDispositionDocument({ disposition: 'safe', holeClass: 'sql-value' })).toEqual([]);
  });

  it('reviews other holes and rejects numeric confidence', () => {
    process.env[FLAG] = '1';
    expect(dispositionOf({ refused: false, witnessFailed: true, holeClass: 'sql-identifier' })).toEqual({
      disposition: 'review',
    });
    expect(dispositionOf({ refused: false, witnessFailed: false, holeClass: 'path-prefix' })).toEqual({
      disposition: 'review',
    });
    expect(dispositionOf({ refused: true, witnessFailed: true, holeClass: 'html-text' })).toEqual({});
    expect(validateDispositionDocument({ rows: [{ confidence: 0.5 }] })).toEqual(['numeric confidence is rejected']);
  });
});
