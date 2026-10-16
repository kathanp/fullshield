import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_HOST';

let savedExitCode: typeof process.exitCode;

beforeEach(() => {
  savedExitCode = process.exitCode;
  process.exitCode = undefined;
});

afterEach(() => {
  process.exitCode = savedExitCode;
  delete process.env[FLAG];
});

async function runCli(args: string[]): Promise<{ out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  await program.parseAsync(['node', 'fullshield', ...args]);
  return { out: out.join('\n'), err: err.join('\n') };
}

describe('fullshield host (Phase 35 CLI)', () => {
  it('refuses to run without --experimental-host', async () => {
    const { err } = await runCli(['host']);
    expect(err).toMatch(/experimental-host/);
    expect(err).toMatch(/FULLSHIELD_EXPERIMENTAL_HOST/);
    expect(process.exitCode).toBe(2);
  });

  it('refuses even when the env flag is set if --experimental-host is missing', async () => {
    process.env[FLAG] = '1';
    const { err } = await runCli(['host']);
    expect(err).toMatch(/experimental-host/);
    expect(process.exitCode).toBe(2);
  });

  it('skips with an info message on macOS/Windows; never requests sudo', async () => {
    const { out, err } = await runCli(['host', '--experimental-host', '--offline', '--attempt-threshold', '3']);
    expect(`${out}\n${err}`).not.toMatch(/sudo/i);
    expect(process.env[FLAG]).toBe('1');
    if (process.platform === 'darwin' || process.platform === 'win32') {
      expect(out).toMatch(/skipped/i);
      expect(out).toMatch(/Linux only/);
      expect(process.exitCode ?? 0).toBe(0);
    } else {
      expect(process.exitCode ?? 0).not.toBe(2);
    }
  });

  it('prints JSON skip payload with --json on macOS/Windows', async () => {
    const { out } = await runCli(['host', '--experimental-host', '--json']);
    if (process.platform === 'darwin' || process.platform === 'win32') {
      const parsed = JSON.parse(out) as { skipped: boolean; findings: unknown[] };
      expect(parsed.skipped).toBe(true);
      expect(parsed.findings).toEqual([]);
    }
  });

  it('does not attach HOST-* to a default scan', async () => {
    const { out } = await runCli(['scan', cleanApp, '--json', '--offline']);
    const parsed = JSON.parse(out) as { findings: Array<{ ruleId: string }> };
    expect(parsed.findings.some((f) => f.ruleId.startsWith('HOST-'))).toBe(false);
  });
});
