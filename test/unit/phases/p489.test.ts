import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase489-holdoutrot.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_HOLDOUTROT = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_HOLDOUTROT;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function registry(names: string[]) {
  return {
    apps: [
      { name: 'seen-app', status: 'seen' },
      ...names.map((name) => ({ name, status: 'untouched' })),
    ],
  };
}

describe('phase 489 holdout rotation', () => {
  it('exits 1 when fewer than two untouched reserves exist', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs489-'));
    const file = join(dir, 'holdouts.json');
    writeFileSync(file, JSON.stringify(registry(['only-one'])));
    const before = createHash('sha256').update(readFileSync(file)).digest('hex');
    const result = run(['--registry', file], true);
    expect(result.status).toBe(1);
    expect(createHash('sha256').update(readFileSync(file)).digest('hex')).toBe(before);
  });

  it('prints a proposal for two reserves and does not write the registry', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs489b-'));
    const file = join(dir, 'holdouts.json');
    writeFileSync(file, JSON.stringify(registry(['reserve-a', 'reserve-b'])));
    const before = createHash('sha256').update(readFileSync(file)).digest('hex');
    const result = run(['--registry', file], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('holdout rotation proposal');
    expect(result.stdout).toContain('reserve-a');
    expect(createHash('sha256').update(readFileSync(file)).digest('hex')).toBe(before);
    const source = readFileSync(script, 'utf8');
    expect(source.includes('writeFile')).toBe(false);
    expect(source.includes('appendFile')).toBe(false);
    expect(source.includes('createWriteStream')).toBe(false);
    expect(source.includes("fs.write")).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run([], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
