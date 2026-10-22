import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase478-fuzzlock.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_FUZZLOCK = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_FUZZLOCK;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 478 lockfile fuzzer', () => {
  it('exits 0 on seeds that parse', () => {
    const result = run(['--parser', 'ir'], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('fuzz lock passed');
  }, 30_000);

  it('fails a planted crash and a mutator that rejects every input', () => {
    const crashed = run(['--parser', 'crash'], true);
    expect(crashed.status).not.toBe(0);
    expect(crashed.stderr).toContain('failed case: crash');
    const rejected = run(['--parser', 'reject'], true);
    expect(rejected.status).not.toBe(0);
    expect(rejected.stderr).toContain('zero successes');
    const harness = `${readFileSync(script, 'utf8')}\n${readFileSync(join(root, 'src', 'phases', 'p478.ts'), 'utf8')}`;
    expect(harness.includes("spawn('npm")).toBe(false);
    expect(harness.includes('spawnSync("npm"')).toBe(false);
    expect(harness.includes("spawnSync('npm")).toBe(false);
  }, 30_000);

  it('does nothing when the flag is off', () => {
    const result = run(['--parser', 'crash'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
