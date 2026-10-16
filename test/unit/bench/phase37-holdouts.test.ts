import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';
import { z } from 'zod';

const root = process.cwd();
const schema = z.object({
  apps: z.array(
    z.object({
      name: z.string().min(1),
      repo: z.string().url(),
      sha: z.string().regex(/^[0-9a-f]{40}$/),
      status: z.enum(['tuning', 'seen', 'untouched']),
      reviewed: z.boolean(),
      firstRunDate: z.string().nullable(),
    }),
  ),
});

describe('Phase 37 holdouts', () => {
  it('matches the holdout schema and keeps three untouched apps unreviewed', () => {
    const doc = schema.parse(JSON.parse(readFileSync(join(root, 'bench', 'holdouts.json'), 'utf8')));
    const untouched = doc.apps.filter((app) => app.status === 'untouched');
    expect(untouched).toHaveLength(3);
    expect(untouched.every((app) => app.reviewed === false && app.firstRunDate === null)).toBe(true);
  });

  it('has no scan result for an untouched app', () => {
    for (const name of ['verademo-javascript', 'serverless-goat', 'mongection']) {
      expect(existsSync(join(root, 'bench', name, 'scan.json'))).toBe(false);
      expect(existsSync(join(root, 'bench', name, 'findings.json'))).toBe(false);
    }
  });

  it('prints a review sheet and refuses to sample an untouched app', () => {
    const sheet = spawnSync(process.execPath, ['bench/review-sheet.mjs'], { cwd: root, encoding: 'utf8' });
    expect(sheet.status).toBe(0);
    expect(sheet.stdout).toContain('verademo-javascript');
    expect(sheet.stdout).toContain('untouched');
    const sample = spawnSync(process.execPath, ['bench/sample-triage.mjs', '--app', 'mongection', '--n', '20'], {
      cwd: root,
      encoding: 'utf8',
    });
    expect(sample.status).toBe(1);
    expect(sample.stderr).toContain('untouched');
  });
});
