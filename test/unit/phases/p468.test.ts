import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase468-synth.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_SYNTH = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_SYNTH;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 468 synthetic witnesses', () => {
  it('repeats the same bytes for one seed and marks the file synthetic', () => {
    const dirA = mkdtempSync(join(tmpdir(), 'fs468a-'));
    const dirB = mkdtempSync(join(tmpdir(), 'fs468b-'));
    expect(run(['--seed', '7', '--out', dirA], true).status).toBe(0);
    expect(run(['--seed', '7', '--out', dirB], true).status).toBe(0);
    const body = readFileSync(join(dirA, 'source.js'), 'utf8');
    expect(body.startsWith('// synthetic\n')).toBe(true);
    expect(readFileSync(join(dirA, 'sink.js')).equals(readFileSync(join(dirB, 'sink.js')))).toBe(true);
    expect(readFileSync(join(dirA, 'sanitizer.js')).equals(readFileSync(join(dirB, 'sanitizer.js')))).toBe(true);
  });

  it('refuses a synthetic path as ground truth and refuses bench output', () => {
    const refuse = spawnSync(
      process.execPath,
      ['--input-type=module', '-e', "import { assertNotGroundTruth } from './scripts/phase468-synth.mjs'; assertNotGroundTruth('test/fixtures/synthetic/a.js');"],
      { cwd: root, encoding: 'utf8' },
    );
    expect(refuse.status).not.toBe(0);
    expect(refuse.stderr).toContain('refuses synthetic');
    const allow = spawnSync(
      process.execPath,
      ['--input-type=module', '-e', "import { assertNotGroundTruth } from './scripts/phase468-synth.mjs'; assertNotGroundTruth('test/fixtures/hand/a.js');"],
      { cwd: root, encoding: 'utf8' },
    );
    expect(allow.status).toBe(0);
    const bench = mkdtempSync(join(tmpdir(), 'fs468bench-'));
    const blocked = run(['--seed', '1', '--out', join(bench, 'bench', 'out')], true);
    expect(blocked.status).not.toBe(0);
    const source = readFileSync(script, 'utf8');
    expect(source.includes('node:http')).toBe(false);
    expect(source.includes('fetch(')).toBe(false);
  });

  it('does nothing when the flag is off', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs468off-'));
    const result = run(['--seed', '1', '--out', dir], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
