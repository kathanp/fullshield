import { readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { formatCliError } from '../../../src/cli/errors.js';
import {
  bumpPullRequestArgs,
  defaultGhRunner,
  ghStatus,
  openBumpPullRequests,
  rankBumpsFromScan,
  rankBumpsJson,
  rankedBumpsFromText,
  type RankedBump,
} from '../../../src/modules/deps/bump-pr.js';

const root = join(import.meta.dirname, '../../..');
const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_BUMP_PR;
  process.exitCode = undefined;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

function finding(partial: Record<string, unknown>): Record<string, unknown> {
  return {
    ruleId: 'DEPS-VULN-001',
    reachability: 'reachable',
    severity: 'high',
    snippet: 'left-pad@1.0.0',
    references: ['GHSA-1'],
    fix: { kind: 'dependency-bump', diff: '# bump left-pad from 1.0.0 to 1.2.0\n' },
    ...partial,
  };
}

describe('phase 557 bump pull requests', () => {
  it('ranks reachable critical before high, then name, then advisory', () => {
    const ranked = rankBumpsFromScan({
      findings: [
        finding({ snippet: 'zebra@1.0.0', severity: 'high', references: ['GHSA-z'], fix: { kind: 'dependency-bump', diff: '# bump zebra from 1.0.0 to 2.0.0\n' } }),
        finding({ snippet: 'alpha@1.0.0', severity: 'critical', references: ['GHSA-a'], fix: { kind: 'dependency-bump', diff: '# bump alpha from 1.0.0 to 1.1.0\n' } }),
        finding({ snippet: 'alpha@1.0.0', severity: 'high', references: ['GHSA-b'], fix: { kind: 'dependency-bump', diff: '# bump alpha from 1.0.0 to 1.0.1\n' } }),
        finding({ reachability: 'not-imported', severity: 'critical' }),
        finding({ reachability: 'reachability-unknown' }),
        finding({ severity: 'medium' }),
        finding({ fix: undefined }),
        finding({ ruleId: 'DEPS-TYPOSQUAT-001' }),
      ],
    });
    expect(ranked.map((row) => `${row.rank}:${row.name}:${row.severity}:${row.advisory}`)).toEqual([
      '1:alpha:critical:GHSA-a',
      '2:alpha:high:GHSA-b',
      '3:zebra:high:GHSA-z',
    ]);
    const again = rankBumpsJson(JSON.stringify({ findings: [
      finding({ snippet: 'zebra@1.0.0', severity: 'high', references: ['GHSA-z'], fix: { kind: 'dependency-bump', diff: '# bump zebra from 1.0.0 to 2.0.0\n' } }),
      finding({ snippet: 'alpha@1.0.0', severity: 'critical', references: ['GHSA-a'], fix: { kind: 'dependency-bump', diff: '# bump alpha from 1.0.0 to 1.1.0\n' } }),
    ] }));
    expect(rankBumpsJson(JSON.stringify({ findings: [
      finding({ snippet: 'alpha@1.0.0', severity: 'critical', references: ['GHSA-a'], fix: { kind: 'dependency-bump', diff: '# bump alpha from 1.0.0 to 1.1.0\n' } }),
      finding({ snippet: 'zebra@1.0.0', severity: 'high', references: ['GHSA-z'], fix: { kind: 'dependency-bump', diff: '# bump zebra from 1.0.0 to 2.0.0\n' } }),
    ] }))).toBe(again);
  });

  it('opens one pull request per row and never merges or comments', async () => {
    const item: RankedBump = {
      name: '@scope/pkg',
      from: '1.0.0',
      to: '1.2.3',
      severity: 'critical',
      reachability: 'reachable',
      advisory: 'GHSA-scope',
      rank: 1,
    };
    const calls: string[][] = [];
    const opened = await openBumpPullRequests([item], (args) => {
      calls.push(args);
      return Promise.resolve({ status: 0, stdout: 'https://example.test/pull/1\n', stderr: '' });
    });
    await expect(openBumpPullRequests([item], () => Promise.resolve({ status: 1, stdout: '', stderr: 'no' }))).rejects.toThrow(/FULLSHIELD_EXPERIMENTAL_BUMP_PR/);
    expect(calls).toEqual([bumpPullRequestArgs(item)]);
    expect(calls[0]?.join('\n')).not.toMatch(/\bmerge\b|createComment|createReview/);
    expect(opened.urls).toEqual(['https://example.test/pull/1']);
  });

  it('maps a missing flag to FS-E020 and does not read the scan file', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_BUMP_PR;
    const err: string[] = [];
    const program = createProgram({
      out: () => undefined,
      err: (text) => err.push(text),
    });
    await program.parseAsync(['node', 'fullshield', 'bumps', 'plan', '--from', 'missing-scan.json']);
    expect(err.join('\n')).toMatch(/FS-E020/);
    expect(formatCliError(new Error('bumps requires FULLSHIELD_EXPERIMENTAL_BUMP_PR=1'))).toMatch(/FS-E020/);
    expect(process.exitCode).toBe(2);
  });

  it('gh status treats a numeric code, a string code, and success differently', () => {
    expect(ghStatus(null)).toBe(0);
    expect(ghStatus({ code: 3 })).toBe(3);
    expect(ghStatus({ code: 'ENOENT' })).toBe(1);
  });

  it('rejects a scan file that is not an object and still runs gh', async () => {
    expect(() => rankedBumpsFromText('not-json')).toThrow(/cannot read bumps file/);
    expect(() => rankedBumpsFromText('null')).toThrow(/cannot read bumps file/);
    const result = await defaultGhRunner(['--version']);
    expect(typeof result.status).toBe('number');
    expect(typeof result.stdout).toBe('string');
  });

  it('nightly template does not merge or comment', async () => {
    const yaml = await readFile(join(root, 'templates/fullshield-bumps.yml'), 'utf8');
    expect(yaml).toMatch(/cron:\s*'0 7 \* \* \*'/);
    expect(yaml).toContain('FULLSHIELD_EXPERIMENTAL_BUMP_PR');
    expect(yaml).not.toMatch(/pr merge|createComment|createReview/);
    expect(yaml).not.toMatch(/^\t/m);
  });
});
