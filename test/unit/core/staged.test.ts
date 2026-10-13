import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runScan } from '../../../src/core/engine.js';

let dir: string;

function git(...args: string[]): void {
  execFileSync('git', ['-C', dir, ...args], { stdio: 'ignore' });
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-staged-'));
  git('init', '--quiet');
  git('config', 'user.email', 'test@example.com');
  git('config', 'user.name', 'Test');
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('scan --staged (pre-commit mode)', () => {
  it('scans only staged files', async () => {
    const fakeKey = 'AKIA' + 'IOSFODNN7EXAMPLE';
    await writeFile(join(dir, 'staged.js'), `const k = "${fakeKey}";\n`);
    await writeFile(join(dir, 'unstaged.js'), `const k = "${'AKIA' + 'XXXXXXXXXXXXXXXB'}";\n`);
    git('add', 'staged.js');

    const result = await runScan({ cwd: dir, modules: ['secrets'], staged: true });
    expect(result.metadata.filesScanned).toBe(1);
    const files = new Set(result.findings.map((f) => f.file));
    expect(files).toContain('staged.js');
    expect(files).not.toContain('unstaged.js');
  });

  it('scans nothing when the index is empty', async () => {
    await writeFile(join(dir, 'a.js'), 'const x = 1;\n');
    const result = await runScan({ cwd: dir, modules: ['secrets'], staged: true });
    expect(result.metadata.filesScanned).toBe(0);
    expect(result.findings).toEqual([]);
  });

  it('fails with a clear error outside a git repository', async () => {
    const plain = await mkdtemp(join(tmpdir(), 'fullshield-nogit-'));
    try {
      await expect(runScan({ cwd: plain, modules: ['secrets'], staged: true })).rejects.toThrow(
        /git repository/i,
      );
    } finally {
      await rm(plain, { recursive: true, force: true });
    }
  });
});
