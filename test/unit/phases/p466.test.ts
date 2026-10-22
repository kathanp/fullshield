import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase466-holdouts.mjs');
const holdouts = join(root, 'bench', 'holdouts.json');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_HOLDOUTS = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_HOLDOUTS;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function rows(patch: Record<string, unknown> = {}) {
  return Array.from({ length: 10 }, (_unused, index) => ({
    name: `row-${index}`,
    repo: `https://example.invalid/row-${index}`,
    sha: 'a'.repeat(40),
    status: 'untouched',
    reviewed: false,
    firstRunDate: '',
    ...patch,
  }));
}

describe('phase 466 holdout rows', () => {
  it('parks when the human has not named ten repos', () => {
    const before = readFileSync(holdouts);
    const result = run([], true);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain('parked (S3): human has not named ten holdout repos');
    expect(readFileSync(holdouts).equals(before)).toBe(true);
  });

  it('passes a schema of ten untouched rows and rejects a results file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs466-'));
    const names = join(dir, 'names.json');
    writeFileSync(names, JSON.stringify(rows()));
    const before = readFileSync(holdouts);
    const ok = run(['--names', names, '--results', dir], true);
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain('schema passes');
    expect(readFileSync(holdouts).equals(before)).toBe(true);
    writeFileSync(join(dir, 'row-0.json'), '{}');
    const blocked = run(['--names', names, '--results', dir], true);
    expect(blocked.status).not.toBe(0);
    expect(blocked.stderr).toContain('results file');
  });

  it('rejects reviewed true and a tuning status', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs466b-'));
    const reviewed = join(dir, 'reviewed.json');
    writeFileSync(reviewed, JSON.stringify(rows({ reviewed: true })));
    const reviewedRun = run(['--names', reviewed], true);
    expect(reviewedRun.status).not.toBe(0);
    expect(reviewedRun.stderr).toContain('reviewed: true');
    const tuning = join(dir, 'tuning.json');
    writeFileSync(tuning, JSON.stringify(rows({ status: 'tuning' })));
    const tuningRun = run(['--names', tuning], true);
    expect(tuningRun.status).not.toBe(0);
    expect(tuningRun.stderr).toContain('untouched');
  });

  it('rejects a duplicate name, a seen status, and a placeholder name', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs466c-'));
    const duplicate = join(dir, 'duplicate.json');
    const copy = rows();
    const head = copy[0];
    if (head === undefined) {throw new Error('missing row');}
    copy[1] = { ...head };
    writeFileSync(duplicate, JSON.stringify(copy));
    const duplicateRun = run(['--names', duplicate], true);
    expect(duplicateRun.status).not.toBe(0);
    expect(duplicateRun.stderr).toContain('duplicate name fails');
    const seen = join(dir, 'seen.json');
    writeFileSync(seen, JSON.stringify(rows({ status: 'seen' })));
    const seenRun = run(['--names', seen], true);
    expect(seenRun.status).not.toBe(0);
    expect(seenRun.stderr).toContain('status seen fails');
    const placeholder = join(dir, 'placeholder.json');
    writeFileSync(placeholder, JSON.stringify(rows().map((row, index) => (index === 0 ? { ...row, name: 'todo' } : row))));
    const placeholderRun = run(['--names', placeholder], true);
    expect(placeholderRun.status).not.toBe(0);
    expect(placeholderRun.stderr).toContain('placeholder name fails');
  });

  it('does nothing when the flag is off', () => {
    const result = run([], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
  });
});
