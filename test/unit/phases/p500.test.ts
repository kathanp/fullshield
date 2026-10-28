import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase500-stability2.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_STABILITY2 = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_STABILITY2;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 500 stability contract', () => {
  it('fails a scratch schema that drops a stable field', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs500-'));
    const schema = join(dir, 'schema.json');
    const required = ['id', 'ruleId', 'module', 'title', 'confidence', 'file', 'line', 'message', 'remediation', 'references', 'trace'];
    writeFileSync(schema, JSON.stringify({ required }));
    const result = run(['--schema', schema, '--bump', 'minor'], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('severity');
    expect(result.stdout.includes('product is complete')).toBe(false);
  });

  it('fails a deprecation removed one minor later and passes a removal two minors later', () => {
    const early = run(['--deprecated', '1.2.0', '--removed', '1.3.0'], true);
    expect(early.status).not.toBe(0);
    expect(early.stderr).toContain('one minor later');
    const later = run(['--deprecated', '1.2.0', '--removed', '1.4.0'], true);
    expect(later.status).toBe(0);
    const version = readFileSync(join(root, 'package.json'), 'utf8');
    expect(version).toContain('"version": "2.3.0"');
  });

  it('omits a rule without the stable bit and leaves a scan snapshot unchanged', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs500b-'));
    const rules = join(dir, 'rules');
    mkdirSync(rules);
    writeFileSync(join(rules, 'STABLE.md'), '---\nstability: stable\n---\n');
    writeFileSync(join(rules, 'EXPERIMENT.md'), '---\nstability: experimental\n---\n');
    const snapshot = join(dir, 'scan.json');
    writeFileSync(snapshot, '{"findings":[]}\n');
    const before = createHash('sha256').update(readFileSync(snapshot)).digest('hex');
    const result = run(['--rules', rules], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('STABLE');
    expect(result.stdout.includes('EXPERIMENT')).toBe(false);
    expect(createHash('sha256').update(readFileSync(snapshot)).digest('hex')).toBe(before);
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--deprecated', '1.2.0', '--removed', '1.3.0'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
