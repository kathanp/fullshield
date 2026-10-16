import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { POLICY_FILE_NAME } from '../../../src/policy/index.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_POLICY';
const vulnApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

let savedExitCode: typeof process.exitCode;
let savedFlag: string | undefined;
const dirs: string[] = [];

beforeEach(() => {
  savedExitCode = process.exitCode;
  process.exitCode = undefined;
  savedFlag = process.env[FLAG];
  delete process.env[FLAG];
});

afterEach(async () => {
  process.exitCode = savedExitCode;
  if (savedFlag === undefined) delete process.env[FLAG];
  else process.env[FLAG] = savedFlag;
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
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

async function writeSqliApp(dir: string, policy: unknown): Promise<void> {
  await writeFile(
    join(dir, 'fullshield.config.json'),
    `${JSON.stringify({ modules: ['sast'], failOn: 'high', ignore: ['node_modules/**'] })}\n`,
  );
  await mkdir(join(dir, 'src'), { recursive: true });
  await writeFile(
    join(dir, 'src', 'index.js'),
    [
      "const express = require('express');",
      'const db = { query() {} };',
      'const app = express();',
      "app.get('/user', (req, res) => {",
      "  db.query('SELECT * FROM users WHERE id = ' + req.query.id);",
      '  res.end();',
      '});',
      '',
    ].join('\n'),
    'utf8',
  );
  await writeFile(join(dir, POLICY_FILE_NAME), `${JSON.stringify(policy, null, 2)}\n`, 'utf8');
}

describe('Phase 34 CLI', () => {
  it('registers scan --pr-summary', () => {
    const program = createProgram();
    const scan = program.commands.find((c) => c.name() === 'scan');
    expect(scan).toBeDefined();
    expect(scan!.options.map((o) => o.long)).toContain('--pr-summary');
  });

  it('refuses --pr-summary without FULLSHIELD_EXPERIMENTAL_POLICY', async () => {
    const { err } = await runCli(['scan', cleanApp, '--pr-summary']);
    expect(err).toMatch(/FULLSHIELD_EXPERIMENTAL_POLICY/);
    expect(process.exitCode).toBe(2);
  });

  it('prints deterministic Markdown for new findings versus baseline', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-prsum-'));
    dirs.push(dir);
    await writeSqliApp(dir, {});
    process.env[FLAG] = '1';
    const first = await runCli(['scan', dir, '--pr-summary', '--modules', 'sast']);
    const second = await runCli(['scan', dir, '--pr-summary', '--modules', 'sast']);
    expect(process.exitCode).toBe(1);
    expect(first.out).toBe(second.out);
    expect(first.out).toMatch(/^# FullShield PR summary\n/);
    expect(first.out).toContain('SAST-SQLI-001');
    expect(first.out).toContain(
      'https://github.com/kathanp/fullshield/blob/main/rules/SAST-SQLI-001.md',
    );
    expect(first.out).not.toMatch(/openai|anthropic|likely-false-positive/i);
  });

  it('exits 1 with a clear message when a policy exception is expired', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-expired-'));
    dirs.push(dir);
    await writeSqliApp(dir, {
      exceptions: [
        {
          ruleId: 'SAST-SQLI-001',
          owner: 'alice',
          reason: 'forgot',
          expires: '2020-01-01',
        },
      ],
    });
    process.env[FLAG] = '1';
    const { err, out } = await runCli(['scan', dir, '--modules', 'sast']);
    expect(process.exitCode).toBe(1);
    expect(err).toMatch(/expired on 2020-01-01/);
    expect(err).toMatch(/alice/);
    expect(out).toContain('SAST-SQLI-001');
  });

  it('exits 2 when an exception is missing owner or expires', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-badpol-'));
    dirs.push(dir);
    await writeSqliApp(dir, {
      exceptions: [{ ruleId: 'SAST-SQLI-001', reason: 'no owner', expires: '2099-01-01' }],
    });
    process.env[FLAG] = '1';
    const { err } = await runCli(['scan', dir, '--modules', 'sast']);
    expect(process.exitCode).toBe(2);
    expect(err).toMatch(/owner/);
  });

  it('default scan of fixture apps is unchanged without the flag', async () => {
    const { out, err } = await runCli(['scan', cleanApp, '--json']);
    expect(err).toBe('');
    const parsed = JSON.parse(out) as { findings: Array<{ ruleId: string }> };
    expect(parsed.findings).toEqual([]);
    expect(process.exitCode ?? 0).toBe(0);

    process.exitCode = undefined;
    const vuln = await runCli(['scan', vulnApp, '--json', '--offline']);
    const report = JSON.parse(vuln.out) as { findings: Array<{ ruleId: string }> };
    expect(report.findings.some((f) => f.ruleId.startsWith('POLICY-'))).toBe(false);
  });
});
