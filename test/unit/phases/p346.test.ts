import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p346.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

const row = {
  state: 'candidate' as const,
  osvId: 'GHSA-0000-0000-0000',
  package: 'fixture-pkg',
  affectedExports: ['fixture-pkg.parse'],
  source: 'https://example.invalid/row',
};

describe('phase 346', () => {
  it('returns no hits when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.querySymbols([row], ['left.parse'])).toEqual([]);
  });

  it('labels a candidate hit unreviewed and skips a rejected row', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.querySymbols([row], ['parse'])[0]?.label).toBe('unreviewed');
    expect(phase.querySymbols([{ ...row, state: 'rejected' }], ['parse'])).toEqual([]);
    expect(phase.validateSymbolRow({ ...row, affectedExports: ['handler'] })).toContain('export-path');
    expect(() => phase.reviewAuthorGuard({ author: 'bot', automation: true, from: 'candidate', to: 'reviewed' })).toThrow(/human/);
  });
});
