import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase482-rulecheck.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_RULECHECK = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_RULECHECK;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function rule(dir: string, id: string, withNegative: boolean) {
  mkdirSync(join(dir, 'rules'), { recursive: true });
  mkdirSync(join(dir, 'fixtures', id), { recursive: true });
  mkdirSync(join(dir, 'mutants'), { recursive: true });
  writeFileSync(
    join(dir, 'rules', `${id}.md`),
    `---\nid: ${id}\nprecision: ungated\n---\nFP paragraph: a human wrote this.\n`,
  );
  writeFileSync(join(dir, 'fixtures', id, 'positive.js'), 'positive\n');
  if (withNegative) {writeFileSync(join(dir, 'fixtures', id, 'negative.js'), 'negative\n');}
  writeFileSync(join(dir, 'mutants', `${id}.js`), 'mutant\n');
}

describe('phase 482 rule checklist', () => {
  it('fails a new rule missing a negative fixture and lists an old one without failing', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs482-'));
    rule(dir, 'OLD', false);
    rule(dir, 'NEW', false);
    const baseline = join(dir, 'baseline.txt');
    writeFileSync(baseline, 'OLD\n');
    const result = run(['--root', dir, '--baseline', baseline], true);
    expect(result.status).not.toBe(0);
    expect(result.stdout).toContain('The checklist is not a review.');
    const doc = JSON.parse(result.stdout.split('\n').slice(1).join('\n')) as { rules: Array<{ ruleId: string; missing: string[] }>; score?: unknown };
    expect(doc.score).toBeUndefined();
    expect(JSON.stringify(doc).includes('"score"')).toBe(false);
    const old = doc.rules.find((row) => row.ruleId === 'OLD');
    const newer = doc.rules.find((row) => row.ruleId === 'NEW');
    expect(old?.missing).toContain('negative');
    expect(newer?.missing).toContain('negative');
  });

  it('passes when the only gap belongs to an old rule', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs482b-'));
    rule(dir, 'OLD', false);
    const baseline = join(dir, 'baseline.txt');
    writeFileSync(baseline, 'OLD\n');
    const result = run(['--root', dir, '--baseline', baseline], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('"missing"');
  });

  it('does nothing when the flag is off', () => {
    const result = run([], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
