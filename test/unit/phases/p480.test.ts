import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase480-detstress.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_DETSTRESS = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_DETSTRESS;
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
