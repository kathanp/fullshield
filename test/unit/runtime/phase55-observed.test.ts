import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { packageFromFileUrl, recordLoaded } from '../../../src/runtime/observed-reach.js';

describe('phase 55 observed reach hook', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH;
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('reads a package name and export from a loaded file URL', () => {
    expect(packageFromFileUrl('file:///app/node_modules/lodash/get.js')).toEqual({
      name: 'lodash',
      exportName: 'get',
    });
    expect(packageFromFileUrl('file:///app/node_modules/express/index.js')).toEqual({
      name: 'express',
      exportName: '.',
    });
    expect(packageFromFileUrl('file:///app/node_modules/@scope/pkg/lib/router.js')).toEqual({
      name: '@scope/pkg',
      exportName: 'lib/router',
    });
    expect(packageFromFileUrl('file:///app/src/index.js')).toBeUndefined();
  });

  it('appends loaded names only when the flag is set and never throws', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fs-observed-'));
    dirs.push(dir);
    await recordLoaded(dir, 'held', '.');
    await expect(readFile(join(dir, '.fullshield', 'observed-reach.json'), 'utf8')).rejects.toThrow();

    process.env.FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH = '1';
    await recordLoaded(dir, 'held', '.');
    await recordLoaded(dir, 'lodash', 'get');
    await recordLoaded(dir, 'held', 'Router');
    const saved = JSON.parse(await readFile(join(dir, '.fullshield', 'observed-reach.json'), 'utf8')) as {
      packages: Record<string, string[]>;
    };
    expect(saved.packages.held).toEqual(['.', 'Router']);
    expect(saved.packages.lodash).toEqual(['get']);

    const fileAsDir = await mkdtemp(join(tmpdir(), 'fs-observed-file-'));
    dirs.push(fileAsDir);
    await writeFile(join(fileAsDir, 'not-a-dir'), 'x');
    await expect(recordLoaded(join(fileAsDir, 'not-a-dir'), 'held', '.')).resolves.toBeUndefined();
  });

  it('performs no network call', async () => {
    const hook = await readFile(join(import.meta.dirname, '../../../src/runtime/observed-reach.ts'), 'utf8');
    const loader = await readFile(join(import.meta.dirname, '../../../src/runtime/rasp/loader.ts'), 'utf8');
    const blob = `${hook}\n${loader}`;
    expect(blob).not.toMatch(/from 'node:(?:http|https|net|dns)'/);
    expect(blob).not.toMatch(/\bfetch\s*\(/);
    expect(blob).not.toContain('undici');

    const dir = await mkdtemp(join(tmpdir(), 'fs-observed-net-'));
    dirs.push(dir);
    process.env.FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH = '1';
    const calls: string[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = ((...args: unknown[]) => {
      calls.push(String(args[0]));
      return Promise.reject(new Error('network'));
    }) as typeof fetch;
    try {
      await recordLoaded(dir, 'held', '.');
    } finally {
      globalThis.fetch = original;
    }
    expect(calls).toEqual([]);
  });
});
