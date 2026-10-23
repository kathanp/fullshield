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

  it('ignores a comment-only hunk and refuses to overwrite a reviewed row', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.candidatesFromDiff(() => '@@\n+ // note\n+ /* block\n+ * star\n+\n', 'https://example.invalid/diff', 'left')).toEqual([]);
    const diff = '@@\n+function parse() {\n+  return 1;\n+exports.other = 1;\n exports.kept = 1;\n';
    const rows = phase.candidatesFromDiff(() => diff, 'https://example.invalid/diff', 'left');
    expect(rows.map((row) => row.exportName)).toEqual(['other', 'parse']);
    const written = phase.writeCandidates([], rows, true);
    expect(written.exitCode).toBe(0);
    expect(written.rows.map((row) => row.state)).toEqual(['candidate', 'candidate']);
    const reviewed = [{ state: 'reviewed' as const, osvId: 'X', package: 'left', affectedExports: ['left.parse'], source: 's' }];
    expect(phase.writeCandidates(reviewed, rows, true)).toMatchObject({ exitCode: 1, rows: reviewed });
    const prior = [{ state: 'candidate' as const, osvId: '', package: 'left', affectedExports: ['left.other'], source: 's' }];
    expect(phase.writeCandidates(prior, rows, true).rows).toHaveLength(3);
  });

  it('does not read candidates when the flag is off', () => {
    expect(() => phase.writeCandidates([], [], true)).toThrow(phase.PatchDiffError);
  });
});
