import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase485-reprokit.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_REPROKIT = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_REPROKIT;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 485 reproduction check', () => {
  it('accepts a matching block and rejects a wrong number', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs485-'));
    const file = join(dir, 'BENCH.md');
    writeFileSync(file, 'numbers: 1\n\n```reproduction\nnode -e console.log(1)\n```\n');
    const before = createHash('sha256').update(readFileSync(file)).digest('hex');
    const ok = run(['--file', file], true);
    expect(ok.status).toBe(0);
    expect(createHash('sha256').update(readFileSync(file)).digest('hex')).toBe(before);
    writeFileSync(file, 'numbers: 1\n\n```reproduction\nnode -e console.log(2)\n```\n');
    const bad = run(['--file', file], true);
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toContain('number mismatch');
  });

  it('refuses curl and an untouched holdout directory name', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs485b-'));
    const registry = join(dir, 'holdouts.json');
    writeFileSync(registry, JSON.stringify({ apps: [{ name: 'mongection', status: 'untouched' }] }));
    const curl = join(dir, 'curl.md');
    writeFileSync(curl, 'numbers: 1\n\n```reproduction\ncurl https://example.invalid\n```\n');
    const refused = run(['--file', curl, '--registry', registry], true);
    expect(refused.status).not.toBe(0);
    expect(refused.stderr).toContain('refused curl');
    const holdout = join(dir, 'holdout.md');
    writeFileSync(holdout, 'numbers: 1\n\n```reproduction\nnode -e console.log(1) mongection\n```\n');
    const blocked = run(['--file', holdout, '--registry', registry], true);
    expect(blocked.status).not.toBe(0);
    expect(blocked.stderr).toContain('refused untouched holdout');
  });

  it('prints no reproduction block when the fence is absent', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs485c-'));
    const file = join(dir, 'plain.md');
    writeFileSync(file, 'numbers: 1\n');
    const result = run(['--file', file], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no reproduction block');
  });
});
