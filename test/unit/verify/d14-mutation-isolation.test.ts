import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();

function gitDiff(): string {
  return spawnSync('git', ['diff', '--exit-code', '--', 'src', 'test'], {
    cwd: root,
    encoding: 'utf8',
  }).stdout ?? '';
}

describe('D14 mutation isolation', () => {
  it('kills a mutation run mid-way and leaves src and test unchanged', async () => {
    const before = gitDiff();
    const child = spawn(process.execPath, [join(root, 'scripts', 'mutation-smoke.mjs')], {
      cwd: root,
      env: { ...process.env, FULLSHIELD_MUTATION_HOLD: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout?.on('data', (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      output += chunk.toString();
    });
    const held = await new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => resolve(false), 30_000);
      const poll = setInterval(() => {
        if (output.includes('mutation-smoke: holding')) {
          clearInterval(poll);
          clearTimeout(timer);
          resolve(true);
        }
      }, 50);
    });
    child.kill('SIGKILL');
    await new Promise((resolve) => child.on('exit', resolve));
    expect(held, output).toBe(true);
    expect(gitDiff()).toBe(before);
  }, 40_000);

  it('a second verify in the same worktree exits FS-E010', () => {
    const lock = join(mkdtempSync(join(tmpdir(), 'fs-lock-')), 'verify.lock');
    writeFileSync(lock, `${process.pid}\n`);
    try {
      const result = spawnSync(process.execPath, [join(root, 'scripts', 'verify.mjs')], {
        cwd: root,
        env: { ...process.env, FULLSHIELD_VERIFY_LOCK: lock },
        encoding: 'utf8',
      });
      expect(result.status).not.toBe(0);
      expect(`${result.stdout}\n${result.stderr}`).toContain('FS-E010');
    } finally {
      rmSync(lock, { force: true });
    }
  });
});
