import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase470-kappa.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_KAPPA = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_KAPPA;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function hash(path: string) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

describe('phase 470 kappa', () => {
  it('matches the hand-computed pair to two decimal places and prints the count', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs470-'));
    const left = join(dir, 'a.json');
    const right = join(dir, 'b.json');
    const rows = (labels: string[]) =>
      JSON.stringify({
        rows: labels.map((label, index) => ({ ruleId: 'SAST-X', id: `i${index}`, label })),
      });
    writeFileSync(left, rows(['tp', 'tp', 'tp', 'fp']));
    writeFileSync(right, rows(['tp', 'tp', 'fp', 'fp']));
    const before = hash(left) + hash(right);
    const result = run(['--a', left, '--b', right], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('kappa=0.50');
    expect(result.stdout).toContain('n=4');
    expect(hash(left) + hash(right)).toBe(before);
  });

  it('prints the count 2 for a pair of size 2', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs470b-'));
    const left = join(dir, 'a.json');
    const right = join(dir, 'b.json');
    const rows = JSON.stringify({
      rows: [
        { ruleId: 'SAST-X', id: 'i0', label: 'tp' },
        { ruleId: 'SAST-X', id: 'i1', label: 'fp' },
      ],
    });
    writeFileSync(left, rows);
    writeFileSync(right, rows);
    const result = run(['--a', left, '--b', right], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('n=2');
  });

  it('prints needs second reviewer for one file and does nothing with the flag off', () => {
    const one = run(['--a', 'only.json'], true);
    expect(one.status).toBe(0);
    expect(one.stdout).toContain('needs second reviewer');
    const off = run([], false);
    expect(off.status).toBe(0);
    expect(off.stdout).toBe('');
  });
});
