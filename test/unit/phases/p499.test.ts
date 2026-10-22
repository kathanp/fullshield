import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase499-backport.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_BACKPORT = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_BACKPORT;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 499 backport check', () => {
  it('exits 1 on a stable-id difference and 0 on an experimental-only difference', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs499-'));
    const left = join(dir, 'left.json');
    const right = join(dir, 'right.json');
    const other = join(dir, 'other');
    writeFileSync(other, 'present');
    writeFileSync(left, JSON.stringify({ findings: [{ ruleId: 'SAST-SQLI-001', file: 'src/app.js', severity: 'high' }] }));
    writeFileSync(right, JSON.stringify({ findings: [{ ruleId: 'SAST-SQLI-001', file: 'src/app.js', severity: 'low' }] }));
    const stable = run(['--other', other, '--left', left, '--right', right, '--stable', 'SAST-SQLI-001'], true);
    expect(stable.status).toBe(1);
    writeFileSync(right, JSON.stringify({ findings: [{ ruleId: 'SAST-EX-001', file: 'src/app.js', severity: 'high' }] }));
    writeFileSync(left, JSON.stringify({ findings: [] }));
    const experimental = run(['--other', other, '--left', left, '--right', right, '--stable', 'SAST-SQLI-001'], true);
    expect(experimental.status).toBe(0);
  });

  it('prints no backport target for a missing path and ignores absolute prefixes', () => {
    const missing = run(['--other', join(tmpdir(), 'fs499-absent')], true);
    expect(missing.status).toBe(0);
    expect(missing.stdout).toContain('no backport target');
    const dir = mkdtempSync(join(tmpdir(), 'fs499b-'));
    const leftRoot = join(dir, 'a');
    const rightRoot = join(dir, 'b');
    const left = join(dir, 'left.json');
    const right = join(dir, 'right.json');
    const other = join(dir, 'other');
    writeFileSync(other, 'present');
    writeFileSync(left, JSON.stringify({ findings: [{ ruleId: 'SAST-SQLI-001', file: join(leftRoot, 'src', 'app.js'), severity: 'high' }] }));
    writeFileSync(right, JSON.stringify({ findings: [{ ruleId: 'SAST-SQLI-001', file: join(rightRoot, 'src', 'app.js'), severity: 'high' }] }));
    const same = run(
      ['--other', other, '--left', left, '--right', right, '--left-root', leftRoot, '--right-root', rightRoot, '--stable', 'SAST-SQLI-001'],
      true,
    );
    expect(same.status).toBe(0);
    const support = run(['--print-support'], true);
    expect(support.stdout).toContain('Supported minor lines');
    expect(support.stdout).toContain('The human backports security fixes for stable rule ids.');
    const source = readFileSync(script, 'utf8');
    expect(source.includes('npm publish')).toBe(false);
    expect(source.includes('git push')).toBe(false);
    expect(source.includes('git merge')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--print-support'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
