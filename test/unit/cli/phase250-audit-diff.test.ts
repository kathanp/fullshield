import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF';
const dirs: string[] = [];

async function runCli(args: string[]): Promise<{ out: string; err: string; code: number | undefined }> {
  const out: string[] = [];
  const err: string[] = [];
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  const previous = process.exitCode;
  process.exitCode = undefined;
  try {
    await program.parseAsync(['node', 'fullshield', ...args]);
    return { out: out.join('\n'), err: err.join('\n'), code: process.exitCode ?? 0 };
  } finally {
    process.exitCode = previous;
  }
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) {await rm(dir, { recursive: true, force: true });}
});

describe('npm-audit-diff', () => {
  it('exits 2 when the flag is off', async () => {
    const { err, code } = await runCli(['npm-audit-diff', '--file', 'missing.json']);
    expect(code).toBe(2);
    expect(err).toMatch(/FS-E017/);
    expect(err).toMatch(/FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF/);
  });

  it('exits 2 when the audit file is missing', async () => {
    process.env[FLAG] = '1';
    const { err, code } = await runCli(['npm-audit-diff', '--file', 'missing-audit.json']);
    expect(code).toBe(2);
    expect(err).toMatch(/FS-E017/);
    expect(err).toMatch(/cannot read npm audit file/);
  });

  it('prints empty sets when the audit and the scan name the same advisory', async () => {
    process.env[FLAG] = '1';
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-audit-diff-'));
    dirs.push(cwd);
    const audit = join(cwd, 'audit.json');
    const scan = join(cwd, 'scan.json');
    await writeFile(audit, JSON.stringify({
      vulnerabilities: {
        leftpad: { version: '1.0.0', via: ['https://github.com/advisories/GHSA-aaaa-bbbb-cccc'] },
      },
    }));
    await writeFile(scan, JSON.stringify({
      findings: [{ ruleId: 'DEPS-VULN-001', references: ['GHSA-aaaa-bbbb-cccc'] }],
    }));
    const { out, err, code } = await runCli(['npm-audit-diff', '--file', audit, '--from', scan]);
    expect(err).toBe('');
    expect(code).toBe(0);
    expect(JSON.parse(out)).toEqual({ onlyAudit: [], onlyScan: [], unmatched: [] });
  });
});
