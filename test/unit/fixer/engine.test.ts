import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
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

  it('refuses --apply outside a git repository without --force', async () => {
    const isolated = await mkdtemp(join(tmpdir(), 'fullshield-fix-nogit-'));
    await writeFile(
      join(isolated, 'app.js'),
      `const express = require('express');\nconst app = express();\napp.use(express.json());\n`,
    );
    await expect(runFix({ cwd: isolated, apply: true, modules: ['config'] })).rejects.toThrow(
      /git repository/i,
    );
    await rm(isolated, { recursive: true, force: true });
  });

  it('refuses --apply on a dirty tree', async () => {
    await writeFile(join(dir, 'extra.txt'), 'dirty\n');
    await expect(runFix({ cwd: dir, apply: true, modules: ['config'] })).rejects.toThrow(/dirty/i);
  });

  it('applies only safe:true fixes on a clean tree (helmet is suggest-only)', async () => {
    const result = await runFix({ cwd: dir, apply: true, modules: ['config'], noBranch: true });
    expect(result.applied).toBe(true);
    expect(result.reverted).toBe(false);
    expect(result.patches.some((p) => p.ruleId === 'CONFIG-HELMET-001' && p.safe === false)).toBe(true);
    const src = await readFile(join(dir, 'app.js'), 'utf8');
    expect(src).not.toContain('helmet');
    expect(src).toContain("express.json({ limit: '100kb' })");
  });

  it('applies helmet only when --unsafe is set', async () => {
    const result = await runFix({
      cwd: dir,
      apply: true,
      unsafe: true,
      modules: ['config'],
      noBranch: true,
    });
    expect(result.applied).toBe(true);
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

  it('with --force, never overwrites a dirty file; user edits survive a failed test run byte-for-byte', async () => {
    const userBytes = Buffer.from(
      "const express = require('express');\nconst app = express();\n// USER-EDIT ☃ unique\napp.use(express.json());\n",
      'utf8',
    );
    await writeFile(join(dir, 'app.js'), userBytes);
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'fix-app', private: true, scripts: { test: 'node -e "process.exit(1)"' } }, null, 2),
    );
    execFileSync('git', ['add', 'package.json'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'failing test'], { cwd: dir });

    const result = await runFix({
      cwd: dir,
      apply: true,
      force: true,
      modules: ['config'],
      noBranch: true,
    });
    expect(result.reverted).toBe(true);
    const after = await readFile(join(dir, 'app.js'));
    expect(after.equals(userBytes)).toBe(true);
  });

  it('with --force, applies safe fixes to clean files and leaves a sibling dirty file untouched', async () => {
    const dirty = Buffer.from('user draft — do not touch\n', 'utf8');
    await writeFile(join(dir, 'notes.txt'), dirty);
    const result = await runFix({
      cwd: dir,
      apply: true,
      force: true,
      modules: ['config'],
      noBranch: true,
    });
    expect(result.applied).toBe(true);
    expect(await readFile(join(dir, 'notes.txt'))).toEqual(dirty);
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toContain("express.json({ limit: '100kb' })");
    expect(await readFile(join(dir, 'app.js'), 'utf8')).not.toContain('helmet');
  });

  it('creates a fix branch unless --no-branch is set', async () => {
    const result = await runFix({ cwd: dir, apply: true, modules: ['config'] });
    expect(result.applied).toBe(true);
    expect(result.branch).toMatch(/^fullshield\/fixes-/);
  });

  it('applies when package.json cannot be parsed (skips the test rerun)', async () => {
    await writeFile(join(dir, 'package.json'), 'not-json');
    execFileSync('git', ['add', 'package.json'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'bad pkg'], { cwd: dir });
    const result = await runFix({ cwd: dir, apply: true, modules: ['config'], noBranch: true });
    expect(result.applied).toBe(true);
    expect(await readFile(join(dir, 'app.js'), 'utf8')).toContain("express.json({ limit: '100kb' })");
  });

  it('unlinks a .gitignore it created when project tests fail', async () => {
    await writeFile(join(dir, '.env'), 'SECRET=1\n');
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'fix-app', private: true, scripts: { test: 'node -e "process.exit(1)"' } }),
    );
    execFileSync('git', ['add', '.'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'env no gitignore'], { cwd: dir });
    const result = await runFix({ cwd: dir, apply: true, modules: ['secrets'], noBranch: true });
    expect(result.reverted).toBe(true);
    expect(existsSync(join(dir, '.gitignore'))).toBe(false);
  });

  it('adds .env to .gitignore for SECRET-ENVFILE-001', async () => {
    await writeFile(join(dir, '.env'), 'SECRET=1\n');
    await writeFile(join(dir, '.gitignore'), 'node_modules/\n');
    execFileSync('git', ['add', '.'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'env'], { cwd: dir });
    const result = await runFix({ cwd: dir, apply: true, modules: ['secrets'], noBranch: true });
    expect(result.applied).toBe(true);
    expect(await readFile(join(dir, '.gitignore'), 'utf8')).toMatch(/\.env/);
  });

  it('--force applies in a non-git directory and restores snapshots if tests fail', async () => {
    const isolated = await mkdtemp(join(tmpdir(), 'fullshield-fix-nongit-'));
    await writeFile(
      join(isolated, 'app.js'),
      `const express = require('express');\nconst app = express();\napp.use(express.json());\n`,
    );
    const before = await readFile(join(isolated, 'app.js'), 'utf8');
    await writeFile(
      join(isolated, 'package.json'),
      JSON.stringify({ name: 'nongit', private: true, scripts: { test: 'node -e "process.exit(1)"' } }),
    );
    const result = await runFix({
      cwd: isolated,
      apply: true,
      force: true,
      modules: ['config'],
      noBranch: true,
    });
    expect(result.reverted).toBe(true);
    expect(await readFile(join(isolated, 'app.js'), 'utf8')).toBe(before);
    await rm(isolated, { recursive: true, force: true });
  });
});
