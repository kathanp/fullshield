import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

function run(script: string, args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

describe('phase 263 semgrep diff', () => {
  it('exports disagreements with a null label and no accuracy claim', () => {
    const dir = mkdtempSync(join(tmpdir(), 'semgrep-'));
    const left = join(dir, 'fullshield.json');
    const right = join(dir, 'semgrep.json');
    const out = join(dir, 'out.json');
    writeFileSync(left, JSON.stringify({ findings: [{ class: 'sqli', file: 'a.js', line: 1 }, { class: 'xss', file: 'a.js', line: 2 }] }));
    writeFileSync(right, JSON.stringify({ findings: [{ class: 'sqli', file: 'a.js', line: 1 }, { class: 'cmdi', file: 'b.js', line: 3 }] }));
    const first = run('scripts/semgrep-diff.mjs', [left, right, out]);
    const second = run('scripts/semgrep-diff.mjs', [left, right, out]);
    expect(first.status).toBe(0);
    expect(first.stdout).toBe(second.stdout);
    const body = JSON.parse(readFileSync(out, 'utf8')) as { disagreements: { label: null }[] };
    expect(body.disagreements.every((row) => row.label === null)).toBe(true);
    expect(readFileSync('scripts/semgrep-diff.mjs', 'utf8').toLowerCase().includes('more accurate')).toBe(false);
  });
});

describe('phase 264 metamorph', () => {
  it('writes a gap report for the seed rule and keeps variants out of fixtures', () => {
    const dir = mkdtempSync(join(tmpdir(), 'meta-'));
    const out = join(dir, 'failures.json');
    const result = run('scripts/metamorph.mjs', ['SAST-SQLI-001', out]);
    expect(result.status).toBe(0);
    const report = JSON.parse(readFileSync(out, 'utf8')) as { rules: string[]; failures: unknown[] };
    expect(report.rules).toEqual(['SAST-SQLI-001']);
    expect(report.failures).toEqual([]);
    expect(readFileSync('scripts/metamorph.mjs', 'utf8')).toContain('default fixture');
  });
});

describe('phase 265 precision gate', () => {
  it('passes, fails, and lists ungated rules without writing floors', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prec-'));
    const labels = join(dir, 'labels.json');
    const floors = join(dir, 'floors.json');
    const many = (rule: string, label: string, count: number) => Array.from({ length: count }, () => ({ rule, label }));
    writeFileSync(labels, JSON.stringify({
      rows: [
        ...many('GOOD', 'tp', 20),
        ...many('BAD', 'fp', 20),
        ...many('SMALL', 'tp', 3),
      ],
    }));
    const floorText = JSON.stringify({ GOOD: 0.5, BAD: 0.5 });
    writeFileSync(floors, floorText);
    const result = run('scripts/precision-gate.mjs', [labels, floors]);
    expect(result.stdout).toContain('inactive until Section 41 item 2');
    expect(result.stdout).toContain('GOOD pass');
    expect(result.stdout).toContain('BAD fail');
    expect(result.stdout).toContain('SMALL ungated');
    expect(result.status).toBe(1);
    expect(readFileSync(floors, 'utf8')).toBe(floorText);
    expect(readFileSync('scripts/precision-gate.mjs', 'utf8').includes('writeFile')).toBe(false);
  });
});
