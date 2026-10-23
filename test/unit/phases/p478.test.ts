import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { fuzzLock, HEADER_SEED, LOCK_SEED, main, PACKUMENT_SEED, parseHeader, parseLock, parsePackument } from '../../../src/phases/p478.js';

const FUZZLOCK = 'FULLSHIELD_EXPERIMENTAL_FUZZLOCK';

function capture(run: () => number): { code: number; stdout: string; stderr: string } {
  let stdout = '';
  let stderr = '';
  const writeOut = process.stdout.write.bind(process.stdout);
  const writeErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  });
  process.stderr.write = ((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  });
  try {
    return { code: run(), stdout, stderr };
  } finally {
    process.stdout.write = writeOut;
    process.stderr.write = writeErr;
  }
}

const root = process.cwd();
const script = join(root, 'scripts', 'phase478-fuzzlock.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_FUZZLOCK = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_FUZZLOCK;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 478 lockfile fuzzer', () => {
  it('exits 0 on seeds that parse', () => {
    const result = run(['--parser', 'ir'], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('fuzz lock passed');
  }, 30_000);

  it('fails a planted crash and a mutator that rejects every input', () => {
    const crashed = run(['--parser', 'crash'], true);
    expect(crashed.status).not.toBe(0);
    expect(crashed.stderr).toContain('failed case: crash');
    const rejected = run(['--parser', 'reject'], true);
    expect(rejected.status).not.toBe(0);
    expect(rejected.stderr).toContain('zero successes');
    const harness = `${readFileSync(script, 'utf8')}\n${readFileSync(join(root, 'src', 'phases', 'p478.ts'), 'utf8')}`;
    expect(harness.includes("spawn('npm")).toBe(false);
    expect(harness.includes('spawnSync("npm"')).toBe(false);
    expect(harness.includes("spawnSync('npm")).toBe(false);
  }, 30_000);

  it('does nothing when the flag is off', () => {
    const result = run(['--parser', 'crash'], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});

describe('phase 478 module', () => {
  it('parses seeds and fails planted parsers', () => {
    process.env[FUZZLOCK] = '1';
    try {
      expect(parseLock(LOCK_SEED)).toBe('ok');
      expect(parseLock('{')).toBe('reject');
      expect(parseLock('{"packages":null}')).toBe('reject');
      expect(parsePackument(PACKUMENT_SEED)).toBe('ok');
      expect(parsePackument('null')).toBe('reject');
      expect(parsePackument('[]')).toBe('reject');
      expect(parsePackument('{"name":""}')).toBe('reject');
      expect(parsePackument('{"name":1}')).toBe('reject');
      expect(parsePackument('1')).toBe('reject');
      expect(parsePackument('{')).toBe('reject');
      expect(parseHeader(HEADER_SEED)).toBe('ok');
      expect(parseHeader('nope')).toBe('reject');
      expect(parseHeader('path:\n')).toBe('reject');
      expect(parseHeader('path: /etc/passwd\n')).toBe('reject');
      expect(parseHeader('path: ../etc/passwd\n')).toBe('reject');
      expect(fuzzLock('ir')).toMatchObject({ code: 0, text: 'fuzz lock passed\n' });
      expect(fuzzLock('crash').text).toContain('failed case: crash');
      expect(fuzzLock('reject').text).toContain('zero successes');
      const ok = capture(() => main(['--parser', 'ir']));
      expect(ok.code).toBe(0);
      expect(ok.stdout).toContain('fuzz lock passed');
      const crashed = capture(() => main(['--parser', 'crash']));
      expect(crashed.code).toBe(1);
      expect(crashed.stderr).toContain('failed case: crash');
      expect(capture(() => main([])).code).toBe(0);
      expect(capture(() => main(['--parser'])).code).toBe(0);
    } finally {
      delete process.env[FUZZLOCK];
    }
  });
});
