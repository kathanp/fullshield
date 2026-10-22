import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase498-buildpin.mjs');
const workflows = join(root, '.github', 'workflows');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_BUILDPIN = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_BUILDPIN;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

const pinned = `name: CI
jobs:
  verify:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1
        with:
          node-version: 22.13.0
          npm-version: 10.9.2
      - run: npm ci --ignore-scripts
`;

describe('phase 498 release-build pins', () => {
  it('fails a floating action tag and an npm install step', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs498-'));
    const file = join(dir, 'ci.yml');
    writeFileSync(file, 'jobs:\n  verify:\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm install\n');
    const result = run(['--workflow', file], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('actions/checkout@v4');
    expect(result.stderr).toContain('sub-point: floating action tag');
    expect(result.stderr).toContain('npm install fails the lint');
    expect(result.stderr).toContain('sub-point: npm install is not npm ci --ignore-scripts');
  });

  it('passes a pinned fixture and parks the repo workflows without rewriting them', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs498b-'));
    const file = join(dir, 'ci.yml');
    writeFileSync(file, pinned);
    expect(run(['--workflow', file], true).status).toBe(0);
    const before = readdirSync(workflows)
      .filter((name) => name.endsWith('.yml'))
      .map((name) => createHash('sha256').update(readFileSync(join(workflows, name))).digest('hex'))
      .join();
    const parked = run(['--workflows', workflows, '--repo'], true);
    expect(parked.status).not.toBe(0);
    expect(parked.stderr).toContain('parked (S3)');
    const after = readdirSync(workflows)
      .filter((name) => name.endsWith('.yml'))
      .map((name) => createHash('sha256').update(readFileSync(join(workflows, name))).digest('hex'))
      .join();
    expect(after).toBe(before);
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--workflows', workflows, '--repo'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
