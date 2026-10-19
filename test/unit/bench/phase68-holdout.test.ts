import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { holdoutPlan, runHoldout } from '../../../bench/holdout-run.mjs';

function apps(names: string[]) {
  return names.map((name) => ({ name, status: 'untouched', reviewed: false, firstRunDate: null }));
}

describe('phase 68 holdout run', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('refuses a missing freeze tag, a rule change, a second run, and a reserve floor', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fs-holdout-'));
    dirs.push(dir);
    const resultsDir = join(dir, 'results');
    const holdoutsPath = join(dir, 'holdouts.json');
    const base = {
      release: '0.4.0',
      resultsDir,
      holdoutsPath,
      changedFiles: [] as string[],
      today: '2026-10-18',
      scan: () => [],
    };
    expect(() => holdoutPlan({ ...base, headTag: 'v0.4.0', apps: apps(['a', 'b', 'c']) })).toThrow(/not tagged/);
    expect(() =>
      holdoutPlan({ ...base, headTag: 'freeze-0.4.0', changedFiles: ['rules/SECRET-AWS-001.md'], apps: apps(['a', 'b', 'c']) }),
    ).toThrow(/changed since/);
    expect(() => holdoutPlan({ ...base, headTag: 'freeze-0.4.0', apps: apps(['a', 'b']) })).toThrow(/fewer than 2/);

    const three = apps(['a', 'b', 'c']);
    await writeFile(holdoutsPath, JSON.stringify({ apps: three }));
    const ran = runHoldout({ ...base, headTag: 'freeze-0.4.0', apps: three });
    expect(ran).toEqual(['a']);
    expect(() => holdoutPlan({ ...base, headTag: 'freeze-0.4.0', apps: apps(['a', 'b', 'c']) })).toThrow(
      /already has a result/,
    );
  });
});
