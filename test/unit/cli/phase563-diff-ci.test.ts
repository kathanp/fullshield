import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runInit } from '../../../src/cli/commands/init.js';

const dirs: string[] = [];

afterEach(async () => {
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

describe('phase 563 recommended diff workflow', () => {
  it('init --recommended writes scan --diff and a plain init does not', async () => {
    const recommended = await mkdtemp(join(tmpdir(), 'fullshield-diff-ci-'));
    dirs.push(recommended);
    const plain = await mkdtemp(join(tmpdir(), 'fullshield-diff-plain-'));
    dirs.push(plain);
    const wrote = await runInit({ cwd: recommended, recommended: true });
    expect(wrote.written).toContain('.github/workflows/fullshield-diff.yml');
    const yaml = await readFile(join(recommended, '.github/workflows/fullshield-diff.yml'), 'utf8');
    expect(yaml).toContain('scan --diff');
    expect(yaml).toContain('FULLSHIELD_EXPERIMENTAL_DIFFSCAN');
    expect(yaml).not.toMatch(/createComment|pr merge/);
    expect(yaml).not.toMatch(/^\t/m);
    const plainResult = await runInit({ cwd: plain });
    expect(plainResult.written).not.toContain('.github/workflows/fullshield-diff.yml');
  });
});
