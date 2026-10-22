import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase486-feedback.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_FEEDBACK = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_FEEDBACK;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 486 local feedback', () => {
  it('stores the fingerprint and note without the source line', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs486-'));
    const scan = join(dir, 'scan.json');
    const unique = 'xyzzy-source-line-must-stay-out';
    writeFileSync(
      scan,
      JSON.stringify({ findings: [{ id: 'fp-1', file: 'a.js', line: 4, snippet: unique }] }),
    );
    const result = run(['--fingerprint', 'fp-1', '--scan', scan, '--note', 'looks safe', '--out', dir], true);
    expect(result.status).toBe(0);
    const saved = readFileSync(join(dir, '.fullshield', 'feedback.json'), 'utf8');
    expect(saved).toContain('fp-1');
    expect(saved).toContain('looks safe');
    expect(saved.includes(unique)).toBe(false);
  });

  it('warns on a synthetic token, still writes, and creates nothing for an unknown fingerprint', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs486b-'));
    const scan = join(dir, 'scan.json');
    writeFileSync(scan, JSON.stringify({ findings: [{ id: 'fp-1', file: 'a.js', line: 1 }] }));
    const token = 'AKIAIOSFODNN7EXAMPLE';
    const warned = run(['--fingerprint', 'fp-1', '--scan', scan, '--note', token, '--out', dir], true);
    expect(warned.status).toBe(0);
    expect(warned.stdout).toContain('local warning: note matches a secret format; file stays local');
    expect(existsSync(join(dir, '.fullshield', 'feedback.json'))).toBe(true);
    const other = mkdtempSync(join(tmpdir(), 'fs486c-'));
    const missing = run(['--fingerprint', 'nope', '--scan', scan, '--note', 'x', '--out', other], true);
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain('FS-E');
    expect(existsSync(join(other, '.fullshield', 'feedback.json'))).toBe(false);
    const template = run(['--print-template'], true);
    expect(template.stdout).toContain('.fullshield/feedback.json');
    const source = readFileSync(script, 'utf8');
    expect(source.includes('node:http')).toBe(false);
    expect(source.includes('node:net')).toBe(false);
  });

  it('exits FS-E when the flag is off', () => {
    const result = run(['--print-template'], false);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('FS-E');
  });
});
