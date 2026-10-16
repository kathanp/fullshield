import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

const vexApp = join(process.cwd(), 'test', 'fixtures', 'vex-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_VEX';

let savedExitCode: typeof process.exitCode;

beforeEach(() => {
  savedExitCode = process.exitCode;
  process.exitCode = undefined;
  delete process.env[FLAG];
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

describe('Phase 31 CLI wiring', () => {
  it('registers vex --format openvex|cyclonedx', () => {
    const program = createProgram();
    const vex = program.commands.find((c) => c.name() === 'vex');
    expect(vex).toBeDefined();
    expect(vex!.options.map((o) => o.long)).toContain('--format');
  });

  it('scan --experimental-vex is registered', () => {
    const program = createProgram();
    const scan = program.commands.find((c) => c.name() === 'scan');
    expect(scan!.options.map((o) => o.long)).toContain('--experimental-vex');
  });

  it('vex refuses without the flag and writes OpenVEX with it', async () => {
    const refused = await runCli(['vex', vexApp, '--format', 'openvex']);
    expect(refused.err).toMatch(/FULLSHIELD_EXPERIMENTAL_VEX/);
    expect(process.exitCode).toBe(2);

    process.exitCode = undefined;
    process.env[FLAG] = '1';
    const ok = await runCli(['vex', vexApp, '--format', 'openvex']);
    expect(ok.err).toBe('');
    const doc = JSON.parse(ok.out) as { statements: unknown[] };
    expect(doc.statements.length).toBeGreaterThan(0);
  });
});
