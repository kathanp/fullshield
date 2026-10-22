import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase472-toolchainpin.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_TOOLCHAINPIN = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_TOOLCHAINPIN;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 472 toolchain pin', () => {
  it('continues when the versions match', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs472-'));
    const pin = join(dir, 'toolchain.json');
    const marker = join(dir, 'ran.txt');
    writeFileSync(pin, JSON.stringify({ node: 'v22.13.0', npm: '10.9.2', semgrep: '1.2.3' }));
    const result = run(
      ['--pin', pin, '--node', 'v22.13.0', '--npm', '10.9.2', '--semgrep', '1.2.3', '--continue-marker', marker],
      true,
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('toolchain match');
    expect(existsSync(marker)).toBe(true);
  });

  it('exits non-zero on a mismatch and does not start the next command', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs472b-'));
    const pin = join(dir, 'toolchain.json');
    const marker = join(dir, 'ran.txt');
    writeFileSync(pin, JSON.stringify({ node: 'v22.13.0', npm: '10.9.2', semgrep: '1.2.3' }));
    const result = run(
      ['--pin', pin, '--node', 'v24.0.0', '--npm', '10.9.2', '--semgrep', '1.2.3', '--continue-marker', marker],
      true,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('pinned v22.13.0');
    expect(result.stderr).toContain('local v24.0.0');
    expect(existsSync(marker)).toBe(false);
    const source = readFileSync(script, 'utf8');
    expect(source.includes('--skip')).toBe(false);
    expect(source.includes('node:http')).toBe(false);
    expect(source.includes('fetch(')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--pin', 'missing.json'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
