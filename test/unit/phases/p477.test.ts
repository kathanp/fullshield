import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase477-fuzzparse.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_FUZZPARSE = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_FUZZPARSE;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 477 parser fuzzer', () => {
  it('parses the current seeds when there are zero mutations', () => {
    const result = run(['--mutations', '0', '--parser', 'ir'], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('fuzz parse passed');
  }, 30_000);

  it('fails a parser that rejects every input and a planted crash', () => {
    const rejected = run(['--parser', 'reject'], true);
    expect(rejected.status).not.toBe(0);
    expect(rejected.stderr).toContain('zero successes');
    const crashed = run(['--parser', 'crash'], true);
    expect(crashed.status).not.toBe(0);
    expect(crashed.stderr).toContain('failed case: crash');
  }, 30_000);

  it('counts a hang as a failed case and never passes source to vm', () => {
    const started = Date.now();
    const result = run(['--parser', 'hang', '--fuel-ms', '150'], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('failed case: hang');
    expect(Date.now() - started).toBeLessThan(10_000);
    const harness = `${readFileSync(script, 'utf8')}\n${readFileSync(join(root, 'src', 'phases', 'p477.ts'), 'utf8')}`;
    expect(harness.includes('node:vm')).toBe(false);
    expect(harness.includes('vm.run')).toBe(false);
    expect(harness.includes('vm.Script')).toBe(false);
  }, 30_000);
});
