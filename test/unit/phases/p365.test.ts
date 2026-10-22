import { describe, expect, it } from 'vitest';

import { enabled, FLAG, gitPinFindings, PHASE_120_FLAG } from '../../../src/phases/p365.js';

describe('phase 365 git pin', () => {
  it('adds nothing when both flags are off', () => {
    expect(enabled()).toBe(false);
    expect(gitPinFindings('github:example/repo#main')).toEqual([]);
  });

  it('reports #main and a semver tag, and keeps both ids when both flags are on', () => {
    process.env[FLAG] = '1';
    process.env[PHASE_120_FLAG] = '1';
    const main = gitPinFindings('github:example/repo#main');
    expect(main.map((row) => row.ruleId).sort()).toEqual(['DEPS-GITDEP-001', 'DEPS-GITPIN-001']);
    const semver = gitPinFindings('git+https://example.invalid/repo.git#semver:^1.0.0');
    expect(semver.map((row) => row.ruleId)).toContain('DEPS-GITPIN-001');
  });

  it('does not report a 40-hex id as unpinned, and still reports the git id when 120 is on', () => {
    process.env[FLAG] = '1';
    process.env[PHASE_120_FLAG] = '1';
    const id = 'a'.repeat(40);
    const findings = gitPinFindings(`git+https://example.invalid/repo.git#${id}`);
    expect(findings.map((row) => row.ruleId)).toEqual(['DEPS-GITDEP-001']);
  });

  it('reports a short SHA because it is not 40 hex characters', () => {
    process.env[FLAG] = '1';
    const findings = gitPinFindings('github:example/repo#abcdef1');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('not 40 hex characters');
  });

  it('does not report a non-git dependency', () => {
    process.env[FLAG] = '1';
    process.env[PHASE_120_FLAG] = '1';
    expect(gitPinFindings('^1.2.3')).toEqual([]);
  });

  it('omits this id when this flag is off and 120 is on', () => {
    process.env[PHASE_120_FLAG] = '1';
    expect(gitPinFindings('github:example/repo#main').map((row) => row.ruleId)).toEqual(['DEPS-GITDEP-001']);
  });
});
