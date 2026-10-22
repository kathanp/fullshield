import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { FLAG, GL_INJECT, scanGitlabCi } from '../../../src/phases/p455.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('phase 455', () => {
  it('reports an interpolated merge request title', () => {
    process.env[FLAG] = '1';
    const findings = scanGitlabCi('gitlab-ci.yml', 'job:\n  script:\n    - echo $CI_MERGE_REQUEST_TITLE\n');
    expect(findings.some((row) => row.ruleId === GL_INJECT)).toBe(true);
    expect(findings[0]?.message).toContain('interpolated');
  });

  it('does not report a job id or a name off the list', () => {
    process.env[FLAG] = '1';
    const job = scanGitlabCi('gitlab-ci.yml', 'job:\n  script:\n    - echo $CI_JOB_ID\n');
    expect(job.some((row) => row.ruleId === GL_INJECT)).toBe(false);
    const other = scanGitlabCi('gitlab-ci.yml', 'job:\n  script:\n    - echo $HOME\n');
    expect(other.some((row) => row.ruleId === GL_INJECT)).toBe(false);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline = [{ ruleId: 'kept', severity: 'high' as const, file: 'gitlab-ci.yml', line: 1, message: 'kept' }];
    expect(scanGitlabCi('gitlab-ci.yml', 'job:\n  script:\n    - echo $CI_MERGE_REQUEST_TITLE\n', baseline)).toEqual(baseline);
    const src = readFileSync(join(root, 'src/phases/p455.ts'), 'utf8');
    expect(src.includes('node:http')).toBe(false);
  });
});
