import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase475-precfw.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_PRECFW = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_PRECFW;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function labels(count: number, label: 'TP' | 'FP', framework: string) {
  return Array.from({ length: count }, () => ({ framework, label }));
}

describe('phase 475 framework precision', () => {
  it('fails a cell under the floor and passes a cell over it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs475-'));
    const floors = join(dir, 'floors.json');
    writeFileSync(floors, JSON.stringify({ express: 0.9, other: 0.5 }));
    const before = createHash('sha256').update(readFileSync(floors)).digest('hex');
    const under = join(dir, 'under.json');
    writeFileSync(under, JSON.stringify({ rows: labels(20, 'TP', 'express') }));
    const failed = run(['--labels', under, '--floors', floors], true);
    expect(failed.status).not.toBe(0);
    const overPath = join(dir, 'over.json');
    writeFileSync(floors, JSON.stringify({ express: 0.5 }));
    const afterRewrite = createHash('sha256').update(readFileSync(floors)).digest('hex');
    writeFileSync(overPath, JSON.stringify({ rows: labels(20, 'TP', 'express') }));
    const passed = run(['--labels', overPath, '--floors', floors], true);
    expect(passed.status).toBe(0);
    expect(createHash('sha256').update(readFileSync(floors)).digest('hex')).toBe(afterRewrite);
    expect(before).not.toBe('');
  });

  it('marks nineteen labels ungated and keeps unknown as its own cell', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs475b-'));
    const floors = join(dir, 'floors.json');
    const rows = join(dir, 'rows.json');
    writeFileSync(floors, JSON.stringify({ express: 0.1 }));
    writeFileSync(rows, JSON.stringify({ rows: [...labels(19, 'TP', 'express'), ...labels(3, 'FP', 'unknown')] }));
    const before = createHash('sha256').update(readFileSync(floors)).digest('hex');
    const result = run(['--labels', rows, '--floors', floors], true);
    expect(result.status).toBe(0);
    const doc = JSON.parse(result.stdout) as { cells: Array<{ framework: string; status: string; n: number }> };
    const express = doc.cells.find((cell) => cell.framework === 'express');
    const unknown = doc.cells.find((cell) => cell.framework === 'unknown');
    expect(express?.status).toBe('ungated');
    expect(express?.n).toBe(19);
    expect(unknown).toBeDefined();
    expect(unknown?.n).toBe(3);
    expect(createHash('sha256').update(readFileSync(floors)).digest('hex')).toBe(before);
  });

  it('does nothing when the flag is off', () => {
    const result = run([], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
