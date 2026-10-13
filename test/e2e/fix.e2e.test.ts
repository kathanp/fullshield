import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeAll, describe, expect, it } from 'vitest';

const root = process.cwd();
const cliPath = join(root, 'dist', 'cli', 'index.js');
const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const dirs: string[] = [];

beforeAll(() => {
  if (!existsSync(cliPath)) throw new Error('built CLI missing');
});

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function runCli(args: string[], cwd: string) {
  return spawnSync(process.execPath, [cliPath, ...args], { encoding: 'utf8', cwd });
}

describe('fix command (built CLI)', () => {
  it('dry-run on a copy of vulnerable-app prints diffs and does not modify files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-fix-e2e-'));
    dirs.push(dir);
    cpSync(vulnerableApp, dir, { recursive: true });
    const before = readFileSync(join(dir, 'src/index.js'), 'utf8');
    const { stdout, status } = runCli(['fix', dir, '--modules', 'config'], dir);
    expect(status).toBe(0);
    expect(stdout).toMatch(/helmet|limit/i);
    expect(readFileSync(join(dir, 'src/index.js'), 'utf8')).toBe(before);
  });

  it('applies safe fixes on a git copy of vulnerable-app', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-fix-apply-'));
    dirs.push(dir);
    cpSync(vulnerableApp, dir, { recursive: true });
    execFileSync('git', ['init'], { cwd: dir });
    execFileSync('git', ['config', 'user.email', 'fix@test.local'], { cwd: dir });
    execFileSync('git', ['config', 'user.name', 'Fix Test'], { cwd: dir });
    execFileSync('git', ['add', '.'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'fixture'], { cwd: dir });
    const { status, stderr } = runCli(['fix', dir, '--apply', '--no-branch', '--modules', 'config'], dir);
    expect(stderr).toBe('');
    expect(status).toBe(0);
    const src = readFileSync(join(dir, 'src/index.js'), 'utf8');
    expect(src).toContain('helmet');
    expect(src).toContain("express.json({ limit: '100kb' })");
  });
});
