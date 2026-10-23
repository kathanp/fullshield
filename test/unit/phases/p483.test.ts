import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { ablate, main, pathHasHoldout } from '../../../src/phases/p483.js';

const ABLATION = 'FULLSHIELD_EXPERIMENTAL_ABLATION';

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
const script = join(root, 'scripts', 'phase483-ablation.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_ABLATION = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_ABLATION;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 483 flag ablation', () => {
  it('writes one unreviewed count row and does not say winner', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs483-'));
    const repo = join(dir, 'app');
    mkdirSync(repo);
    writeFileSync(join(repo, 'app.js'), "function handler(req) {\n  db.query('SELECT * FROM users WHERE id = ' + req.query.id);\n}\n");
    const registry = join(dir, 'holdouts.json');
    writeFileSync(registry, JSON.stringify({ apps: [{ name: 'mongection' }] }));
    const before = createHash('sha256').update(readFileSync(join(root, 'package.json'))).digest('hex');
    const result = run(['--repo', repo, '--registry', registry, '--flag', 'FULLSHIELD_EXPERIMENTAL_IR'], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('"unreviewed":true');
    expect(result.stdout.includes('winner')).toBe(false);
    const doc = JSON.parse(result.stdout) as { unreviewed: boolean; rows: Array<{ flag: string; count: number }> };
    expect(doc.unreviewed).toBe(true);
    expect(doc.rows).toHaveLength(1);
    expect(doc.rows[0]?.count).toBeGreaterThan(0);
    expect(createHash('sha256').update(readFileSync(join(root, 'package.json'))).digest('hex')).toBe(before);
  }, 30_000);

  it('refuses a path that names a holdout', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs483b-'));
    const repo = join(dir, 'mongection');
    mkdirSync(repo);
    writeFileSync(join(repo, 'app.js'), 'const n = 1;\n');
    const registry = join(dir, 'holdouts.json');
    writeFileSync(registry, JSON.stringify({ apps: [{ name: 'mongection' }] }));
    const result = run(['--repo', repo, '--registry', registry, '--flag', 'FULLSHIELD_EXPERIMENTAL_IR'], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('holdout path refused');
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--repo', root, '--registry', 'nope.json'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});

describe('phase 483 module', () => {
  it('ablates flags through the exported functions', async () => {
    process.env[ABLATION] = '1';
    const dir = mkdtempSync(join(tmpdir(), 'fs483-mod-'));
    const repo = join(dir, 'app');
    mkdirSync(repo);
    writeFileSync(join(repo, 'app.js'), "function handler(req) {\n  db.query('SELECT * FROM users WHERE id = ' + req.query.id);\n}\n");
    const registry = join(dir, 'holdouts.json');
    writeFileSync(registry, JSON.stringify({ apps: [{ name: 'mongection' }, {}, { name: 1 }] }));
    process.env.FULLSHIELD_EXPERIMENTAL_IR = '1';
    try {
      expect(pathHasHoldout(join('tmp', 'mongection', 'app'), ['mongection'])).toBe('mongection');
      expect(pathHasHoldout('C:\\mongection\\app', ['mongection'])).toBe('mongection');
      expect(pathHasHoldout(join('tmp', 'app'), ['mongection'])).toBeUndefined();
      const kept = await ablate(repo, ['FULLSHIELD_EXPERIMENTAL_IR'], []);
      expect(process.env.FULLSHIELD_EXPERIMENTAL_IR).toBe('1');
      expect(kept).toContain('"unreviewed":true');
      delete process.env.FULLSHIELD_EXPERIMENTAL_IR;
      const cleared = await ablate(repo, ['FULLSHIELD_EXPERIMENTAL_OTHER'], []);
      expect(process.env.FULLSHIELD_EXPERIMENTAL_OTHER).toBeUndefined();
      expect(cleared).toContain('FULLSHIELD_EXPERIMENTAL_OTHER');
      await expect(ablate(join(dir, 'mongection'), [], ['mongection'])).rejects.toThrow(/holdout path refused/);
      const result = await capture(() => main(['--repo', repo, '--registry', registry, '--flag', 'FULLSHIELD_EXPERIMENTAL_IR', '--flag']));
      expect(result.code).toBe(0);
      expect(result.stdout).toContain('"unreviewed":true');
      expect((await capture(() => main(['--repo', repo]))).code).toBe(2);
      expect((await capture(() => main([]))).code).toBe(2);
      const held = join(dir, 'mongection');
      mkdirSync(held);
      const refused = await capture(() => main(['--repo', held, '--registry', registry, '--flag', 'FULLSHIELD_EXPERIMENTAL_IR']));
      expect(refused.code).toBe(1);
      expect(refused.stderr).toContain('holdout path refused');
      writeFileSync(registry, JSON.stringify({}));
      const empty = await capture(() => main(['--repo', repo, '--registry', registry]));
      expect(empty.code).toBe(0);
    } finally {
      delete process.env[ABLATION];
      delete process.env.FULLSHIELD_EXPERIMENTAL_IR;
      delete process.env.FULLSHIELD_EXPERIMENTAL_OTHER;
    }
  }, 60_000);
});
