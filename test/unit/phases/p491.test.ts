import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase491-provshape.mjs');
const publish = join(root, '.github', 'workflows', 'publish.yml');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_PROVSHAPE = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_PROVSHAPE;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

const complete = `name: Publish
jobs:
  publish:
    steps:
      - name: provenance
        env:
          subject: fullshield
          buildType: https://example.invalid/build
          isolation: hosted
`;

describe('phase 491 provenance shape', () => {
  it('fails a fixture that deletes subject and does not rewrite the file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs491-'));
    const file = join(dir, 'publish.yml');
    writeFileSync(file, complete.replace('          subject: fullshield\n', ''));
    const before = createHash('sha256').update(readFileSync(file)).digest('hex');
    const result = run(['--workflow', file], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('missing field subject');
    expect(createHash('sha256').update(readFileSync(file)).digest('hex')).toBe(before);
  });

  it('passes a complete fixture and parks the real workflow on the missing field', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs491b-'));
    const file = join(dir, 'publish.yml');
    writeFileSync(file, complete);
    const ok = run(['--workflow', file], true);
    expect(ok.status).toBe(0);
    const before = createHash('sha256').update(readFileSync(publish)).digest('hex');
    const parked = run(['--workflow', publish, '--repo'], true);
    expect(parked.status).not.toBe(0);
    expect(parked.stderr).toContain('parked (S3)');
    expect(parked.stderr).toContain('missing field subject');
    expect(createHash('sha256').update(readFileSync(publish)).digest('hex')).toBe(before);
    const source = readFileSync(script, 'utf8');
    expect(source.includes('node:http')).toBe(false);
  });

  it('rejects an empty subject, a non-https build type, and an unknown isolation', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs491c-'));
    const file = join(dir, 'publish.yml');
    writeFileSync(file, complete.replace('subject: fullshield', 'subject:'));
    expect(run(['--workflow', file], true).stderr).toContain('sub-point: subject is empty');
    writeFileSync(file, complete.replace('https://example.invalid/build', 'local'));
    expect(run(['--workflow', file], true).stderr).toContain('sub-point: build type is not an https URL');
    writeFileSync(file, complete.replace('isolation: hosted', 'isolation: trusted'));
    const isolation = run(['--workflow', file], true);
    expect(isolation.status).not.toBe(0);
    expect(isolation.stderr).toContain('sub-point: isolation is not hosted, self-hosted, or sandboxed');
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--workflow', publish, '--repo'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
