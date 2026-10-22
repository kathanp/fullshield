import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase483-ablation.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_ABLATION = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_ABLATION;
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
