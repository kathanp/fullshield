import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase495-permworkers.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_PERMWORKERS = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_PERMWORKERS;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 495 permission workers', () => {
  it('reads a file inside the repo and fails a read of /etc/passwd', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs495-'));
    const repo = join(dir, 'repo');
    const cache = join(dir, 'cache');
    mkdirSync(repo);
    mkdirSync(cache);
    const inside = join(repo, 'inside.txt');
    writeFileSync(inside, 'ok');
    const allowed = run(['--repo', repo, '--cache', cache, '--target', inside], true);
    expect(allowed.status).toBe(0);
    expect(allowed.stdout).toContain('read-ok');
    const denied = run(['--repo', repo, '--cache', cache, '--target', '/etc/passwd'], true);
    expect(denied.status).not.toBe(0);
    expect(denied.stdout).toContain('read-fail');
  });

  it('omits child-process permission and adds no fallback row', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs495b-'));
    const repo = join(dir, 'repo');
    const cache = join(dir, 'cache');
    mkdirSync(repo);
    mkdirSync(cache);
    const printed = run(['--repo', repo, '--cache', cache, '--target', join(repo, 'x'), '--print-args'], true);
    expect(printed.status).toBe(0);
    expect(printed.stdout.includes('--allow-child-process')).toBe(false);
    expect(printed.stdout).toContain('--permission');
    const off = run(['--repo', repo, '--cache', cache, '--target', join(repo, 'x'), '--print-args'], false);
    expect(off.stdout.includes('--permission')).toBe(false);
    const bad = run(['--check-fallback', '--rows', JSON.stringify([{ capability: 'fs' }])], true);
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toContain('fallback without a reason');
    const source = readFileSync(script, 'utf8');
    expect(source.includes('FALLBACK_ROWS = []')).toBe(true);
    expect(source.includes('node:vm')).toBe(false);
  });
});
