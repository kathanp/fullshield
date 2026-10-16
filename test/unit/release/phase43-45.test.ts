import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

describe('Phases 43 and 45', () => {
  it('lists every experimental flag as unmet', () => {
    const report = spawnSync(process.execPath, ['scripts/promotion-report.mjs'], {
      cwd: process.cwd(),
      encoding: 'utf8',
    });
    expect(report.status).toBe(0);
    expect(report.stdout).toContain('FULLSHIELD_EXPERIMENTAL_TAINT_V2');
    expect(report.stdout).toContain('unmet');
    expect(report.stdout).not.toContain('| promote |');
  });

  it('pins project workflow actions by commit SHA', () => {
    const dir = join(process.cwd(), '.github', 'workflows');
    for (const name of readdirSync(dir)) {
      const text = readFileSync(join(dir, name), 'utf8');
      expect(text, name).not.toMatch(/uses:\s+\S+@v\d/);
    }
  });

  it('pins ten real-world repos and does not claim a precision rate', () => {
    const doc = JSON.parse(readFileSync(join(process.cwd(), 'bench', 'realworld.json'), 'utf8')) as {
      repos: Array<{ sha: string }>;
    };
    expect(doc.repos).toHaveLength(10);
    expect(doc.repos.every((repo) => /^[0-9a-f]{40}$/.test(repo.sha))).toBe(true);
    const benchmark = readFileSync(join(process.cwd(), 'BENCHMARK.md'), 'utf8');
    expect(benchmark).toContain('not sampled');
  });
});
