import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runFix } from '../../../src/fixer/index.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-fix-'));
  execFileSync('git', ['init'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 'fix@test.local'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Fix Test'], { cwd: dir });
  await writeFile(
    join(dir, 'app.js'),
    `const express = require('express');\nconst app = express();\napp.use(express.json());\n`,
  );
  await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'fix-app', private: true }, null, 2));
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-m', 'init'], { cwd: dir });
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('fix engine', () => {
  it('dry-run prints diffs and does not write files', async () => {
    const result = await runFix({ cwd: dir, modules: ['config'] });
    expect(result.applied).toBe(false);
    expect(result.patches.length).toBeGreaterThan(0);
    expect(result.patches.some((p) => p.diff.includes('helmet'))).toBe(true);
    const src = await readFile(join(dir, 'app.js'), 'utf8');
    expect(src).not.toContain('helmet');
  });

  it('refuses --apply on a dirty tree', async () => {
    await writeFile(join(dir, 'extra.txt'), 'dirty\n');
    await expect(runFix({ cwd: dir, apply: true, modules: ['config'] })).rejects.toThrow(/dirty/i);
  });

  it('applies safe fixes on a clean tree and keeps them when tests pass or are absent', async () => {
    const result = await runFix({ cwd: dir, apply: true, modules: ['config'], noBranch: true });
    expect(result.applied).toBe(true);
    expect(result.reverted).toBe(false);
    const src = await readFile(join(dir, 'app.js'), 'utf8');
    expect(src).toContain('helmet');
    expect(src).toContain("express.json({ limit: '100kb' })");
  });

  it('reverts the tree when the project test script fails', async () => {
    const before = await readFile(join(dir, 'app.js'), 'utf8');
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'fix-app', private: true, scripts: { test: 'node -e "process.exit(1)"' } }, null, 2),
    );
    execFileSync('git', ['add', 'package.json'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'failing test'], { cwd: dir });

    const result = await runFix({ cwd: dir, apply: true, modules: ['config'], noBranch: true });
    expect(result.reverted).toBe(true);
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toBe(before);
  });
});
