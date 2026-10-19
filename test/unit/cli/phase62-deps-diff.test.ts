import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { diffLockedPackages, lockAtRef, packagesFromLock, releaseAgeLabel } from '../../../src/deps-diff/index.js';

const dirs: string[] = [];

describe('phase 62 lockfile diff', () => {
  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('reports added, removed, upgraded, and downgraded packages using git show only', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-deps-diff-'));
    dirs.push(dir);
    const oldLock = JSON.stringify({
      name: 'app',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { left: '1.0.0', gone: '1.0.0', down: '2.0.0' } },
        'node_modules/left': { version: '1.0.0' },
        'node_modules/gone': { version: '1.0.0' },
        'node_modules/down': { version: '2.0.0' },
      },
    });
    const newLock = JSON.stringify({
      name: 'app',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { left: '1.2.0', added: '2.0.0', down: '1.0.0' } },
        'node_modules/left': { version: '1.2.0' },
        'node_modules/added': { version: '2.0.0' },
        'node_modules/down': { version: '1.0.0' },
      },
    });
    execFileSync('git', ['init'], { cwd: dir });
    execFileSync('git', ['config', 'user.email', 'diff@test.local'], { cwd: dir });
    execFileSync('git', ['config', 'user.name', 'Diff Test'], { cwd: dir });
    await writeFile(join(dir, 'package-lock.json'), oldLock);
    execFileSync('git', ['add', 'package-lock.json'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'old'], { cwd: dir });
    const calls: string[][] = [];
    const shown = await lockAtRef(dir, 'HEAD', async (cwd, args) => {
      calls.push(args);
      if (args[0] !== 'show') throw new Error('unexpected git command');
      return readFile(join(cwd, 'package-lock.json'), 'utf8');
    });
    expect(calls.every((args) => args[0] === 'show')).toBe(true);
    expect(calls.some((args) => args.includes('checkout'))).toBe(false);
    const before = packagesFromLock(shown.file, shown.text);
    const after = packagesFromLock('package-lock.json', newLock);
    const changes = diffLockedPackages(before.packages, after.packages, after.direct);
    expect(changes.find((change) => change.name === 'added')?.change).toBe('added');
    expect(changes.find((change) => change.name === 'gone')?.change).toBe('removed');
    expect(changes.find((change) => change.name === 'left')?.change).toBe('upgraded');
    expect(changes.find((change) => change.name === 'down')?.change).toBe('downgraded');
    expect(releaseAgeLabel(new Date(Date.now() - 3_600_000).toISOString(), Date.now())).toBe('new-release');
    expect(releaseAgeLabel(undefined, Date.now())).toBe('unknown');
  });
});
