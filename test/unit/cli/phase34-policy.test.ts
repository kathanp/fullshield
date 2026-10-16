import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { POLICY_FILE_NAME } from '../../../src/policy/index.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_POLICY';
const goldens = join(process.cwd(), 'test', 'fixtures', 'policy');

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
    JSON.stringify({ modules: ['sast'], failOn: 'high', ignore: ['**/*.test.ts'] }),
  );
  await mkdir(join(dir, 'src'), { recursive: true });
  await writeFile(
    join(dir, 'src', 'index.js'),
    [
      "const express = require('express');",
      'const db = { query: () => {} };',
      'const app = express();',
      "app.get('/user', (req, res) => {",
      "  db.query('SELECT * FROM users WHERE id = ' + req.query.id);",
      '  res.end();',
      '});',
      '',
    ].join('\n'),
  );
  if (policy !== undefined) {
    await writeFile(join(dir, POLICY_FILE_NAME), `${JSON.stringify(policy, null, 2)}\n`);
  }
}

describe('Phase 34 CLI policy + --pr-summary', () => {
  it('registers --pr-summary on scan', () => {
    const program = createProgram();
    const scan = program.commands.find((c) => c.name() === 'scan');
    expect(scan).toBeDefined();
    expect(scan!.options.map((o) => o.long)).toContain('--pr-summary');
  });

  it('refuses --pr-summary without FULLSHIELD_EXPERIMENTAL_POLICY=1', async () => {
    const { err } = await runCli(['scan', '.', '--pr-summary']);
    expect(err).toMatch(/FULLSHIELD_EXPERIMENTAL_POLICY/);
    expect(process.exitCode).toBe(2);
  });

  it('fails CI with a clear message when an exception is expired', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-policy-cli-'));
    dirs.push(dir);
    await writeSqliApp(dir, {
      exceptions: [
        {
          ruleId: 'SAST-SQLI-001',
          owner: 'alice@example.com',
          reason: 'legacy query',
          expires: '2020-01-01',
        },
      ],
    });
    process.env[FLAG] = '1';
    const { err } = await runCli(['scan', dir, '--fail-on', 'high']);
    expect(err).toMatch(/expired/i);
    expect(err).toMatch(/SAST-SQLI-001/);
    expect(err).toMatch(/2020-01-01/);
    expect(process.exitCode).toBe(1);
  });

  it('rejects a policy exception without owner at load time (exit 2)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-policy-cli-'));
    dirs.push(dir);
    await writeSqliApp(dir, {
      exceptions: [{ ruleId: 'SAST-SQLI-001', reason: 'no owner', expires: '2099-12-31' }],
    });
    process.env[FLAG] = '1';
    const { err } = await runCli(['scan', dir]);
    expect(err).toMatch(/owner/);
    expect(process.exitCode).toBe(2);
  });

  it('prints a deterministic PR summary of new findings versus baseline', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-prsum-'));
    dirs.push(dir);
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ modules: ['sast'] }));
    await mkdir(join(dir, 'src'), { recursive: true });
    await writeFile(join(dir, 'src', 'db.js'), 'module.exports = {};\n');
    process.env[FLAG] = '1';
    const { out, err } = await runCli(['scan', dir, '--pr-summary', '--modules', 'sast']);
    expect(err).toBe('');
    expect(out.startsWith('# FullShield PR summary\n')).toBe(true);
    expect(out).toContain('versus baseline.');
    expect(out).not.toMatch(/AI |openai|triage/i);
    const empty = readFileSync(join(goldens, 'pr-summary-empty.md'), 'utf8').trimEnd();
    expect(out.trimEnd()).toBe(empty);
  });
});
