import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';

const dirs: string[] = [];

function run(root: string) {
  return spawnSync(process.execPath, ['scripts/doc-version-check.mjs', '--root', root], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('doc-version-check', () => {
  it('fails when a doc names a different current version', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs-doc-'));
    dirs.push(dir);
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ version: '1.0.1' }));
    writeFileSync(join(dir, 'README.md'), '**v1.0.0**\n');
    const result = run(dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('**v1.0.0**');
    expect(result.stderr).toContain('package.json is 1.0.1');
  });

  it('passes when the named version matches package.json', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs-doc-'));
    dirs.push(dir);
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ version: '1.0.1' }));
    writeFileSync(join(dir, 'README.md'), 'FullShield v1.0.1 — scanned\n');
    const result = run(dir);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('doc-version-check: ok');
  });
});
