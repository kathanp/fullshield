import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase488-fpcorpus.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_FPCORPUS = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_FPCORPUS;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 488 false-positive corpus', () => {
  it('fails a reappearance and passes when the rule file names it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs488-'));
    const corpus = join(dir, 'false-positives.json');
    const findings = join(dir, 'findings.json');
    const rule = join(dir, 'RULE.md');
    writeFileSync(corpus, JSON.stringify({ items: [{ fingerprint: 'fp1', reason: 'human marked this' }] }));
    writeFileSync(findings, JSON.stringify({ findings: [{ id: 'fp1' }] }));
    writeFileSync(rule, 'no note yet\n');
    const failed = run(['--corpus', corpus, '--findings', findings, '--rule', rule], true);
    expect(failed.status).not.toBe(0);
    writeFileSync(rule, 'fp1 why: the witness no longer matches the sink\n');
    const passed = run(['--corpus', corpus, '--findings', findings, '--rule', rule], true);
    expect(passed.status).toBe(0);
  });

  it('prints the empty sentence and rejects an empty reason', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs488b-'));
    const empty = join(dir, 'empty.json');
    writeFileSync(empty, JSON.stringify({ items: [] }));
    const result = run(['--corpus', empty], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no false-positive corpus');
    const bad = join(dir, 'bad.json');
    writeFileSync(bad, JSON.stringify({ items: [{ fingerprint: 'fp1', reason: '' }] }));
    const schema = run(['--corpus', bad, '--findings', empty], true);
    expect(schema.status).not.toBe(0);
    expect(schema.stderr).toContain('empty reason');
    expect(existsSync(join(root, 'quality', 'false-positives.json'))).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run([], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
