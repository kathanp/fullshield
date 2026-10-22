import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p347.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 347', () => {
  it('refuses when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(() => phase.candidatesFromDiff(() => '', 'https://example.invalid/diff', 'left')).toThrow(phase.PatchDiffError);
  });

  it('names an added function and does not write when write is false', () => {
    process.env[phase.FLAG] = '1';
    const diff = '@@\n function parse() {\n+  return 1;\n';
    const rows = phase.candidatesFromDiff(() => diff, 'https://example.invalid/diff', 'left');
    expect(rows.map((row) => row.exportName)).toContain('parse');
    const kept = phase.writeCandidates([], rows, false);
    expect(kept.rows).toEqual([]);
  });
});
