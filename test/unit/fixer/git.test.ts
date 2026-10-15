import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createFixBranch, isDirty, isGitRepo, listDirtyPaths } from '../../../src/fixer/git.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-git-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('fixer git helpers', () => {
  it('isGitRepo is false outside a repository', async () => {
    expect(await isGitRepo(dir)).toBe(false);
  });

  it('detects a dirty tree and lists dirty paths including untracked and renamed files', async () => {
    execFileSync('git', ['init'], { cwd: dir });
    execFileSync('git', ['config', 'user.email', 'git@test.local'], { cwd: dir });
    execFileSync('git', ['config', 'user.name', 'Git Test'], { cwd: dir });
    await writeFile(join(dir, 'tracked.txt'), 'a\n');
    await writeFile(join(dir, 'old-name.txt'), 'rename-me\n');
    execFileSync('git', ['add', '.'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'init'], { cwd: dir });

    expect(await isGitRepo(dir)).toBe(true);
    expect(await isDirty(dir)).toBe(false);
    expect(await listDirtyPaths(dir)).toEqual(new Set());

    await writeFile(join(dir, 'tracked.txt'), 'changed\n');
    await writeFile(join(dir, 'untracked.txt'), 'new\n');
    execFileSync('git', ['mv', 'old-name.txt', 'new-name.txt'], { cwd: dir });

    expect(await isDirty(dir)).toBe(true);
    const dirty = await listDirtyPaths(dir);
    expect(dirty.has('tracked.txt')).toBe(true);
    expect(dirty.has('untracked.txt')).toBe(true);
    expect(dirty.has('new-name.txt') || dirty.has('old-name.txt')).toBe(true);
  });

  // Windows rejects `"` in filenames (CreateFile ENOENT). This case is POSIX-only.
  it.skipIf(process.platform === 'win32')('lists dirty paths that include a quoted filename', async () => {
    execFileSync('git', ['init'], { cwd: dir });
    execFileSync('git', ['config', 'user.email', 'git@test.local'], { cwd: dir });
    execFileSync('git', ['config', 'user.name', 'Git Test'], { cwd: dir });
    await writeFile(join(dir, 'tracked.txt'), 'a\n');
    execFileSync('git', ['add', '.'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'init'], { cwd: dir });
    await writeFile(join(dir, 'file "quoted".txt'), 'q\n');
    const withQuote = await listDirtyPaths(dir);
    expect([...withQuote].some((p) => p.includes('quoted'))).toBe(true);
  });

  it('createFixBranch returns a fullshield/fixes-* name', async () => {
    execFileSync('git', ['init'], { cwd: dir });
    execFileSync('git', ['config', 'user.email', 'git@test.local'], { cwd: dir });
    execFileSync('git', ['config', 'user.name', 'Git Test'], { cwd: dir });
    await writeFile(join(dir, 'a.txt'), 'a\n');
    execFileSync('git', ['add', '.'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'init'], { cwd: dir });
    const name = await createFixBranch(dir);
    expect(name).toMatch(/^fullshield\/fixes-\d+$/);
  });
});
