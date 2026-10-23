import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase494-depmin.mjs');
const packageJson = join(root, 'package.json');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_DEPMIN = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_DEPMIN;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 494 hard dependencies', () => {
  it('parks because this package already has hard dependencies and does not edit them', () => {
    const before = createHash('sha256').update(readFileSync(packageJson)).digest('hex');
    const result = run(['--package', packageJson], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('parked (S3): hard dependencies already exist');
    expect(result.stderr).toContain('sub-point: allow list stays empty');
    expect(result.stderr).toContain('sub-point: later edits are R1');
    expect(result.stderr).toContain('sub-point: peer express is optional');
    expect(createHash('sha256').update(readFileSync(packageJson)).digest('hex')).toBe(before);
  });

  it('matches an empty scratch manifest and fails leftpad or a required peer', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs494-'));
    const empty = join(dir, 'empty.json');
    writeFileSync(empty, JSON.stringify({ dependencies: {}, peerDependencies: { yaml: '*' }, peerDependenciesMeta: { yaml: { optional: true } } }));
    expect(run(['--check', '--package', empty], true).status).toBe(0);
    const leftpad = join(dir, 'leftpad.json');
    writeFileSync(leftpad, JSON.stringify({ dependencies: { leftpad: '1.0.0' } }));
    const extra = run(['--check', '--package', leftpad], true);
    expect(extra.status).not.toBe(0);
    expect(extra.stderr).toContain('leftpad');
    const peer = join(dir, 'peer.json');
    writeFileSync(peer, JSON.stringify({ dependencies: {}, peerDependencies: { yaml: '*' } }));
    const peerRun = run(['--check', '--package', peer], true);
    expect(peerRun.status).not.toBe(0);
    expect(peerRun.stderr).toContain('optional: true');
  });

  it('does nothing when the flag is off', () => {
    const result = run(['--package', packageJson], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
