import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase476-perfpage.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_PERFPAGE = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_PERFPAGE;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 476 performance page', () => {
  it('shows a fixture number and says the page is not a gate', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs476-'));
    const file = join(dir, 'perf.json');
    const out = join(dir, 'page.html');
    writeFileSync(file, JSON.stringify({ unreviewed: true, milliseconds: 42 }));
    const result = run(['--file', file, '--out', out], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('This page is not a gate.');
    expect(result.stdout).toContain('42');
    expect(existsSync(join(dir, 'threshold.json'))).toBe(false);
  });

  it('exits 0 for a large number and leaves a missing file as missing', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs476b-'));
    const file = join(dir, 'perf-large.json');
    writeFileSync(file, JSON.stringify({ unreviewed: true, milliseconds: 999999 }));
    const result = run(['--file', file, '--file', join(dir, 'absent.json')], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('999999');
    expect(result.stdout).toContain('missing');
    const source = readFileSync(script, 'utf8');
    expect(source.includes('threshold')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--file', 'nope.json'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
