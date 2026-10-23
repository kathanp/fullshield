import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { byteMatch, main, threeRuns, unorderedMapDouble } from '../../../src/phases/p480.js';

const DETSTRESS = 'FULLSHIELD_EXPERIMENTAL_DETSTRESS';

async function capture(run: () => Promise<number>): Promise<{ code: number; stdout: string; stderr: string }> {
  let stdout = '';
  let stderr = '';
  const writeOut = process.stdout.write.bind(process.stdout);
  const writeErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  }) as typeof process.stderr.write;
  try {
    const code = await run();
    return { code, stdout, stderr };
  } finally {
    process.stdout.write = writeOut;
    process.stderr.write = writeErr;
  }
}

const root = process.cwd();
const script = join(root, 'scripts', 'phase480-detstress.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_DETSTRESS = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_DETSTRESS;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 480 determinism', () => {
  it('matches three scans of one fixture', () => {
    const dir = join(tmpdir(), 'fs480-app');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'app.js'), "function handler(req) {\n  db.query('SELECT * FROM users WHERE id = ' + req.query.id);\n}\n");
    const result = run(['--dir', dir], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('runs match');
  }, 30_000);

  it('fails a planted unordered map and has no retry loop', () => {
    const result = run(['--double'], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('finding bytes differ');
    const source = `${readFileSync(script, 'utf8')}\n${readFileSync(join(root, 'src', 'phases', 'p480.ts'), 'utf8')}`;
    expect(source.includes('retry')).toBe(false);
  }, 30_000);

  it('does nothing when the flag is off', () => {
    const result = run(['--double'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});

describe('phase 480 module', () => {
  it('compares runs through the exported functions', async () => {
    process.env[DETSTRESS] = '1';
    const previousPool = process.env.UV_THREADPOOL_SIZE;
    try {
      expect(byteMatch([])).toBe(false);
      expect(byteMatch(['a', 'a'])).toBe(true);
      expect(byteMatch(['a', 'b'])).toBe(false);
      const pair = unorderedMapDouble();
      expect(pair[0]).not.toBe(pair[1]);
      expect(byteMatch(pair)).toBe(false);
      const doubled = await capture(() => main(['--double']));
      expect(doubled.code).toBe(1);
      expect(doubled.stderr).toContain('finding bytes differ');
      expect((await capture(() => main([]))).code).toBe(2);
      expect((await capture(() => main(['--dir']))).code).toBe(2);
      const dir = join(tmpdir(), 'fs480-mod');
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'app.js'), "function handler(req) {\n  db.query('SELECT * FROM users WHERE id = ' + req.query.id);\n}\n");
      const runs = await threeRuns(dir);
      expect(byteMatch(runs)).toBe(true);
      const result = await capture(() => main(['--dir', dir]));
      expect(result.code).toBe(0);
      expect(result.stdout).toContain('runs match');
    } finally {
      delete process.env[DETSTRESS];
      if (previousPool === undefined) {delete process.env.UV_THREADPOOL_SIZE;}
      else {process.env.UV_THREADPOOL_SIZE = previousPool;}
    }
  }, 90_000);
});
