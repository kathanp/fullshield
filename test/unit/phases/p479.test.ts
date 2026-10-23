import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase479-nodediff.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_NODEDIFF = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_NODEDIFF;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 479 node finding diff', () => {
  it('matches identical finding JSON', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs479-'));
    const body = JSON.stringify({ findings: [{ ruleId: 'SAST-SQLI-001', file: 'app.js', line: 3, severity: 'high' }] });
    const left = join(dir, 'a.json');
    const right = join(dir, 'b.json');
    writeFileSync(left, body);
    writeFileSync(right, body);
    const result = run(['--left', left, '--right', right], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('findings match');
  });

  it('fails a planted timestamp difference and has no skip list', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs479b-'));
    const left = join(dir, 'a.json');
    const right = join(dir, 'b.json');
    writeFileSync(left, JSON.stringify({ findings: [{ ruleId: 'R', file: 'a.js', line: 1, severity: 'high' }] }));
    writeFileSync(right, JSON.stringify({ findings: [{ ruleId: 'R', file: 'a.js', line: 1, severity: 'high', timestamp: '2020-01-01' }] }));
    const result = run(['--left', left, '--right', right], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('finding bytes differ');
    const source = readFileSync(script, 'utf8');
    expect(source.includes('skipList')).toBe(false);
    expect(source.includes('skip list')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run([], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
