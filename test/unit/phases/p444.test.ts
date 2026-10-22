import { afterEach, describe, expect, it } from 'vitest';

import { attachOwners, enabled, FLAG, FsError, type OwnedFinding } from '../../../src/phases/p444.js';

afterEach(() => {
  delete process.env[FLAG];
});

const finding: OwnedFinding = { ruleId: 'SAST-SQLI-001', file: 'src/a.js', line: 3, severity: 'high' };

const codeowners = ['* @everyone', 'src/*.js @app', 'src/a.js @security', '# comment', ''].join('\n');

describe('phase 444 CODEOWNERS', () => {
  it('adds no owner field when the flag is off', () => {
    expect(enabled()).toBe(false);
    const result = attachOwners([finding], 'src/a.js\n* @guessed');
    expect(result).toEqual([finding]);
    expect(result[0]).not.toHaveProperty('owner');
  });

  it('gives the file the last matching owner', () => {
    process.env[FLAG] = '1';
    const owned = attachOwners([{ ...finding, file: 'src\\a.js' }, { ...finding, file: 'lib/b.js' }], codeowners);
    expect(owned[0]?.owner).toBe('@security');
    expect(owned[1]?.owner).toBe('@everyone');
  });

  it('throws on a syntax error and does not guess an owner', () => {
    process.env[FLAG] = '1';
    const rows = [finding];
    expect(() => attachOwners(rows, '* @everyone\nbroken')).toThrow(FsError);
    expect(() => attachOwners(rows, '* @everyone\nbroken')).toThrow('FS-E CODEOWNERS syntax error');
    expect(rows[0]).not.toHaveProperty('owner');
    expect(attachOwners([finding], '# only a comment\n')[0]?.owner).toBe('unowned');
  });
});
