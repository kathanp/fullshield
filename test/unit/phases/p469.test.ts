import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase469-cweindex.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_CWEINDEX = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_CWEINDEX;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function layout(dir: string, rule: string, withNegative: boolean) {
  mkdirSync(join(dir, 'rules'), { recursive: true });
  mkdirSync(join(dir, 'fixtures', 'R1'), { recursive: true });
  writeFileSync(join(dir, 'rules', 'R1.md'), `---\nid: R1\ncwe: CWE-89\n---\n${rule}\n`);
  writeFileSync(join(dir, 'fixtures', 'R1', 'positive.js'), 'positive\n');
  if (withNegative) {writeFileSync(join(dir, 'fixtures', 'R1', 'negative.js'), 'negative\n');}
}

describe('phase 469 CWE fixture index', () => {
  it('fails a rule that is missing a negative fixture', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs469-'));
    layout(dir, 'rule', false);
    const result = run(['--root', dir], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('missing a negative fixture');
  });

  it('accepts cwe none and rejects an exemption without a reason', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs469b-'));
    mkdirSync(join(dir, 'rules'), { recursive: true });
    writeFileSync(join(dir, 'rules', 'POLICY.md'), '---\nid: POLICY\ncwe: none\nreason: policy check\n---\n');
    const ok = run(['--root', dir], true);
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain('Q10 is still required');
    writeFileSync(join(dir, 'out-of-scope.json'), JSON.stringify([{ ruleId: 'POLICY', reason: '' }]));
    writeFileSync(join(dir, 'rules', 'POLICY.md'), '---\nid: POLICY\ncwe: CWE-1\n---\n');
    const bad = run(['--root', dir], true);
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toContain('without a reason');
    const source = readFileSync(script, 'utf8');
    expect(source.includes('unlink')).toBe(false);
    expect(source.includes('node:http')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--root', root], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
