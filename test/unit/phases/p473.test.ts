import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase473-compare2.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_COMPARE2 = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_COMPARE2;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 473 comparison map', () => {
  it('prints a reviewed row and omits an unreviewed count', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs473-'));
    const map = join(dir, 'comparison-map.json');
    const body = JSON.stringify({
      rows: [
        { name: 'reviewed-row', reviewed: true, count: 4 },
        { name: 'hidden-row', reviewed: false, count: 17 },
      ],
    });
    writeFileSync(map, body);
    const before = createHash('sha256').update(body).digest('hex');
    const result = run(['--map', map], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('reviewed-row');
    expect(result.stdout).toContain('4');
    expect(result.stdout.includes('17')).toBe(false);
    expect(result.stdout.includes('hidden-row')).toBe(false);
    expect(createHash('sha256').update(readFileSync(map)).digest('hex')).toBe(before);
  });

  it('prints the empty sentence and does not import an HTTP client', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs473b-'));
    const map = join(dir, 'empty.json');
    writeFileSync(map, JSON.stringify({ rows: [] }));
    const result = run(['--map', map], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no reviewed comparison rows');
    const source = readFileSync(script, 'utf8');
    expect(source.includes('node:http')).toBe(false);
    expect(source.includes('node:https')).toBe(false);
    expect(source.includes('fetch(')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run([], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
