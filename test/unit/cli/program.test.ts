import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');

let savedExitCode: typeof process.exitCode;

beforeEach(() => {
  savedExitCode = process.exitCode;
  process.exitCode = undefined;
});

afterEach(() => {
  process.exitCode = savedExitCode;
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

describe('fullshield scan (CLI)', () => {
  it('scans clean-app with --json and exits 0', async () => {
    const { out, err } = await runCli(['scan', cleanApp, '--json']);
    expect(err).toBe('');
    const parsed = JSON.parse(out) as {
      findings: unknown[];
      summary: { total: number };
      metadata: { modulesRun: string[] };
    };
    expect(parsed.findings).toEqual([]);
    expect(parsed.summary.total).toBe(0);
    expect(parsed.metadata.modulesRun).toEqual([]);
    expect(process.exitCode ?? 0).toBe(0);
  });

  it('prints a human-readable report by default', async () => {
    const { out } = await runCli(['scan', cleanApp]);
    expect(out).toContain('FullShield v');
    expect(out).toContain('No findings');
    expect(process.exitCode ?? 0).toBe(0);
  });

  it('does not fail vulnerable-app in phase 1 (zero modules implemented)', async () => {
    const { out } = await runCli(['scan', vulnerableApp, '--fail-on', 'high', '--json']);
    const parsed = JSON.parse(out) as { summary: { total: number } };
    expect(parsed.summary.total).toBe(0);
    expect(process.exitCode ?? 0).toBe(0);
  });

  it('accepts a --modules subset', async () => {
    const { out } = await runCli(['scan', cleanApp, '--modules', 'secrets,sast', '--json']);
    const parsed = JSON.parse(out) as { metadata: { modulesRequested: string[] } };
    expect(parsed.metadata.modulesRequested).toEqual(['secrets', 'sast']);
  });

  it('exits 2 on an invalid --fail-on severity', async () => {
    const { err } = await runCli(['scan', cleanApp, '--fail-on', 'severe']);
    expect(err).toContain('invalid --fail-on severity "severe"');
    expect(process.exitCode).toBe(2);
  });

  it('exits 2 on an unknown module name', async () => {
    const { err } = await runCli(['scan', cleanApp, '--modules', 'sast,magic']);
    expect(err).toContain('unknown module "magic"');
    expect(process.exitCode).toBe(2);
  });

  it('exits 2 when the scan path does not exist', async () => {
    const { err } = await runCli(['scan', join(cleanApp, 'nope')]);
    expect(err).toContain('not a directory');
    expect(process.exitCode).toBe(2);
  });

  it('exits 2 when an explicit config file is missing', async () => {
    const { err } = await runCli(['scan', cleanApp, '--config', join(cleanApp, 'missing.json')]);
    expect(err).toContain('cannot read config file');
    expect(process.exitCode).toBe(2);
  });
});
