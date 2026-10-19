import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { advisoriesCleared, diffLockedPackages, lockAtRef, packagesFromLock, registryRecord, releaseAgeLabel } from '../../../src/deps-diff/index.js';

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
    expect(
      advisoriesCleared(
        [{ name: 'left', version: '1.0.0', id: 'GHSA-1', severity: 'high' }],
        [{ name: 'left', version: '1.2.0', id: 'GHSA-2', severity: 'low' }],
      ).map((row) => row.id),
    ).toEqual(['GHSA-1']);
  });

  it('reads publish age from registry.npmjs.org and stays on the cache when offline', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-registry-'));
    dirs.push(dir);
    const calls: string[] = [];
    const record = await registryRecord('left-pad', '1.0.0', {
      cacheDir: dir,
      offline: false,
      fetchImpl: async (input) => {
        const url = String(input);
        calls.push(url);
        const host = new URL(url).hostname;
        if (host !== 'registry.npmjs.org') throw new Error(`unexpected host ${host}`);
        return new Response(
          JSON.stringify({
            'dist-tags': { latest: '1.0.0' },
            time: { '1.0.0': new Date(Date.now() - 80 * 3_600_000).toISOString() },
            versions: { '1.0.0': { scripts: {} } },
          }),
          { status: 200 },
        );
      },
    });
    expect(calls).toEqual(['https://registry.npmjs.org/left-pad']);
    expect(record.latest).toBe('1.0.0');
    expect(record.hasInstallScript).toBe(false);
    expect(releaseAgeLabel(record.publishedAt, Date.now())).toBe('aged');
    const offline = await registryRecord('missing', '1.0.0', {
      cacheDir: dir,
      offline: true,
      fetchImpl: async () => {
        throw new Error('offline must not fetch');
      },
    });
    expect(offline.latest).toBeUndefined();
  });
});
