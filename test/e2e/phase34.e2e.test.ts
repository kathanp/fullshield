import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

const root = process.cwd();
const cli = join(root, 'dist', 'cli', 'index.js');
const vulnApp = join(root, 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(root, 'test', 'fixtures', 'clean-app');
const golden = join(root, 'test', 'fixtures', 'policy', 'pr-summary.md');
const emptyGolden = join(root, 'test', 'fixtures', 'policy', 'pr-summary-empty.md');

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function runCli(
  args: string[],
  env: NodeJS.ProcessEnv = {},
  cwd = root,
): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function writeSqliApp(policy: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'fullshield-p34-'));
  dirs.push(dir);
  writeFileSync(
    join(dir, 'fullshield.config.json'),
    `${JSON.stringify({ modules: ['sast'], failOn: 'high', ignore: ['node_modules/**'] })}\n`,
  );
  mkdirSync(join(dir, 'src'));
  writeFileSync(
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
  );
  writeFileSync(join(dir, 'fullshield.policy.json'), `${JSON.stringify(policy, null, 2)}\n`);
  return dir;
}

describe('Phase 34 CLI (built)', () => {
  it('refuses --pr-summary without FULLSHIELD_EXPERIMENTAL_POLICY', () => {
    const result = runCli(['scan', cleanApp, '--pr-summary'], { FULLSHIELD_EXPERIMENTAL_POLICY: '' });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/FULLSHIELD_EXPERIMENTAL_POLICY/);
  });

  it('fails CI with a clear message when a policy exception is expired', () => {
    const dir = writeSqliApp({
      exceptions: [
        {
          ruleId: 'SAST-SQLI-001',
          owner: 'alice',
          reason: 'forgot',
          expires: '2020-01-01',
        },
      ],
    });
    const result = runCli(['scan', dir, '--modules', 'sast'], { FULLSHIELD_EXPERIMENTAL_POLICY: '1' });
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/expired on 2020-01-01/);
    expect(result.stderr).toMatch(/alice/);
  });

  it('prints --pr-summary Markdown that is stable across two runs', () => {
    const dir = writeSqliApp({});
    const env = { FULLSHIELD_EXPERIMENTAL_POLICY: '1' };
    const a = runCli(['scan', dir, '--pr-summary', '--modules', 'sast'], env);
    const b = runCli(['scan', dir, '--pr-summary', '--modules', 'sast'], env);
    expect(a.stdout).toBe(b.stdout);
    expect(a.stdout).toMatch(/^# FullShield PR summary\n/);
    expect(a.stdout).toContain('SAST-SQLI-001');
    expect(a.stdout).toContain(
      'https://github.com/kathanp/fullshield/blob/main/rules/SAST-SQLI-001.md',
    );
    expect(a.stdout).not.toMatch(/openai|anthropic|likely-false-positive/i);
  });

  it('ships PR summary golden files used by unit tests', () => {
    expect(existsSync(golden)).toBe(true);
    expect(existsSync(emptyGolden)).toBe(true);
    expect(readFileSync(golden, 'utf8')).toContain('SAST-SQLI-001');
    expect(readFileSync(emptyGolden, 'utf8')).toContain('0 new finding(s) versus baseline');
  });

  it('default scan of vulnerable-app and clean-app adds no new POLICY rule ids', () => {
    const vuln = runCli(['scan', vulnApp, '--json', '--offline'], { FULLSHIELD_EXPERIMENTAL_POLICY: '' });
    const clean = runCli(['scan', cleanApp, '--json'], { FULLSHIELD_EXPERIMENTAL_POLICY: '' });
    const vulnReport = JSON.parse(vuln.stdout) as { findings: Array<{ ruleId: string }> };
    const cleanReport = JSON.parse(clean.stdout) as {
      findings: Array<{ ruleId: string; severity: string }>;
    };
    expect(vulnReport.findings.some((f) => f.ruleId.startsWith('POLICY-'))).toBe(false);
    expect(cleanReport.findings.filter((f) => f.severity === 'high' || f.severity === 'critical')).toEqual(
      [],
    );
    expect(clean.status).toBe(0);
  });
});
