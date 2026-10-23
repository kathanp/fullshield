import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { fuzz, main, parseIr, plantHang, SEEDS } from '../../../src/phases/p477.js';

const FUZZPARSE = 'FULLSHIELD_EXPERIMENTAL_FUZZPARSE';

async function capture(run: () => Promise<number>): Promise<{ code: number; stdout: string; stderr: string }> {
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
    const code = await run();
    return { code, stdout, stderr };
  } finally {
    process.stdout.write = writeOut;
    process.stderr.write = writeErr;
  }
}

const root = process.cwd();
const script = join(root, 'scripts', 'phase477-fuzzparse.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) {env.FULLSHIELD_EXPERIMENTAL_FUZZPARSE = '1';}
  else {delete env.FULLSHIELD_EXPERIMENTAL_FUZZPARSE;}
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

describe('phase 477 parser fuzzer', () => {
  it('parses the current seeds when there are zero mutations', () => {
    const result = run(['--mutations', '0', '--parser', 'ir'], true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('fuzz parse passed');
  }, 30_000);

  it('fails a parser that rejects every input and a planted crash', () => {
    const rejected = run(['--parser', 'reject'], true);
    expect(rejected.status).not.toBe(0);
    expect(rejected.stderr).toContain('zero successes');
    const crashed = run(['--parser', 'crash'], true);
    expect(crashed.status).not.toBe(0);
    expect(crashed.stderr).toContain('failed case: crash');
  }, 30_000);

  it('counts a hang as a failed case and never passes source to vm', () => {
    const started = Date.now();
    const result = run(['--parser', 'hang', '--fuel-ms', '150'], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('failed case: hang');
    expect(Date.now() - started).toBeLessThan(10_000);
    const harness = `${readFileSync(script, 'utf8')}\n${readFileSync(join(root, 'src', 'phases', 'p477.ts'), 'utf8')}`;
    expect(harness.includes('node:vm')).toBe(false);
    expect(harness.includes('vm.run')).toBe(false);
    expect(harness.includes('vm.Script')).toBe(false);
  }, 30_000);
});

describe('phase 477 module', () => {
  it('parses seeds and reports reject, crash, and hang', async () => {
    process.env[FUZZPARSE] = '1';
    try {
      expect(SEEDS.length).toBeGreaterThan(0);
      expect(parseIr(SEEDS[0].source)).toBe('ok');
      expect(parseIr('const =')).toBe('crash');
      expect(['ok', 'reject', 'crash']).toContain(parseIr(1 as unknown as string));
      const passed = await fuzz({ mutations: 1, parser: 'ir', fuelMs: 50 });
      expect(passed.code).toBe(0);
      expect(passed.text).toContain('fuzz parse passed');
      expect((await fuzz({ mutations: 0, parser: 'reject', fuelMs: 50 })).text).toContain('zero successes');
      expect((await fuzz({ mutations: 0, parser: 'crash', fuelMs: 50 })).text).toContain('failed case: crash');
      const hang = await fuzz({ mutations: 0, parser: 'hang', fuelMs: 150 });
      expect(hang.code).toBe(1);
      expect(hang.text).toContain('failed case: hang');
      await plantHang(30);
      const ok = await capture(() => main(['--mutations', '0', '--parser', 'ir']));
      expect(ok.code).toBe(0);
      expect(ok.stdout).toContain('fuzz parse passed');
      const bad = await capture(() => main(['--parser', 'crash']));
      expect(bad.code).toBe(1);
      expect(bad.stderr).toContain('failed case: crash');
      const rejected = await capture(() => main(['--parser', 'reject']));
      expect(rejected.code).toBe(1);
      expect(rejected.stderr).toContain('zero successes');
      expect((await capture(() => main(['--mutations']))).code).toBe(0);
      expect((await capture(() => main(['--fuel-ms']))).code).toBe(0);
    } finally {
      delete process.env[FUZZPARSE];
    }
  }, 30_000);
});
