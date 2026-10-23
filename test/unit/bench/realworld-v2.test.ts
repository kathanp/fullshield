import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const SCRIPT = 'scripts/realworld-v2.mjs';

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

describe('phase 266 realworld corpus v2', () => {
  it('accepts the 50 verified pins and prints every stratum', () => {
    const result = run([]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('pins 50');
    for (const stratum of ['express', 'fastify', 'nest', 'next', 'koa-hono', 'monorepo', 'electron', 'ts-heavy', 'js-only']) {
      expect(result.stdout).toContain(stratum);
    }
    expect(result.stdout.includes('gap')).toBe(false);
    const file = JSON.parse(readFileSync('bench/realworld-v2.json', 'utf8')) as { repos: unknown[] };
    expect(file.repos).toHaveLength(50);
    const frozen = readFileSync('bench/realworld.json', 'utf8');
    expect(frozen.includes('realworld-v2')).toBe(false);
  });

  it('rejects a missing sha, a non-hex sha, and a duplicate name', () => {
    const dir = mkdtempSync(join(tmpdir(), 'realworld-v2-'));
    const base = {
      name: 'express',
      repo: 'https://github.com/expressjs/express.git',
      sha: 'a419aa7350389a275ab45fde2e849ed1f02449ef',
      stratum: 'express',
    };
    const missing = join(dir, 'missing.json');
    writeFileSync(missing, JSON.stringify({ repos: [{ ...base, sha: undefined }] }));
    expect(run([missing]).status).not.toBe(0);

    const bad = join(dir, 'bad.json');
    writeFileSync(bad, JSON.stringify({ repos: [{ ...base, sha: 'not-a-sha' }] }));
    expect(run([bad]).status).not.toBe(0);

    const dup = join(dir, 'dup.json');
    writeFileSync(dup, JSON.stringify({
      repos: [
        base,
        { ...base, repo: 'https://github.com/fastify/fastify.git', sha: '37df44a421817e7bb048fce834bf691abb0999d6', stratum: 'fastify' },
      ],
    }));
    expect(run([dup]).stderr).toContain('duplicate name');
  });

  it('refuses an install argument', () => {
    const result = run(['--npm-install']);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('refuses install');
  });
});
