import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, runHookHarness } from '../../../src/runtime/exp/p394.js';

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('phase 394 hook harness', () => {
  it('writes nothing useful when the flag is off', async () => {
    expect(enabled()).toBe(false);
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-p394-'));
    dirs.push(dir);
    const report = runHookHarness([{ name: 'sql', run: () => undefined }], join(dir, 'out.json'));
    expect(report.rows).toEqual([]);
  });

  it('writes one unreviewed row per hook and does not fail a slow hook', async () => {
    process.env[FLAG] = '1';
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-p394-'));
    dirs.push(dir);
    const out = join(dir, 'out.json');
    const report = runHookHarness([{ name: 'sql', run: () => undefined }], out, 5);
    expect(report.reviewed).toBe(false);
    expect(report.unreviewed).toBe(true);
    expect(report.rows.map((row) => row.hook)).toEqual(['sql']);
    const written = JSON.parse(await readFile(out, 'utf8')) as { reviewed: boolean };
    expect(written.reviewed).toBe(false);
  });

  it('fails the harness when a hook throws', async () => {
    process.env[FLAG] = '1';
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-p394-'));
    dirs.push(dir);
    expect(() => runHookHarness([{ name: 'sql', run: () => {
      throw new Error('hook');
    } }], join(dir, 'out.json'), 1)).toThrow(/hook/);
  });
});
