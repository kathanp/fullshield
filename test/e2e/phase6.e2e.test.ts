import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { validateSarif21 } from '../../src/reporters/sarif.js';

const root = process.cwd();
const cliPath = join(root, 'dist', 'cli', 'index.js');
const vulnerableApp = join(root, 'test', 'fixtures', 'vulnerable-app');

function runCli(
  args: string[],
  cwd?: string,
): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [cliPath, ...args], {
    encoding: 'utf8',
    cwd,
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

const dirs: string[] = [];

beforeAll(() => {
  if (!existsSync(cliPath)) throw new Error('built CLI missing');
});

afterEach(() => {
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('Phase 6 reporters, baseline, suppression (built CLI)', () => {
  it('writes a schema-valid SARIF 2.1.0 file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-sarif-'));
    dirs.push(dir);
    const sarifPath = join(dir, 'out.sarif');
    const { status } = runCli(['scan', vulnerableApp, '--sarif', sarifPath, '--modules', 'sast']);
    expect(status).toBe(1);
    const doc = JSON.parse(readFileSync(sarifPath, 'utf8')) as unknown;
    expect(validateSarif21(doc)).toEqual([]);
  });

  it('writes markdown and html reports', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-rep-'));
    dirs.push(dir);
    const md = join(dir, 'out.md');
    const html = join(dir, 'out.html');
    runCli(['scan', vulnerableApp, '--markdown', md, '--html', html, '--modules', 'sast']);
    expect(readFileSync(md, 'utf8')).toContain('# FullShield report');
    expect(readFileSync(html, 'utf8')).toContain('<!DOCTYPE html>');
  });

  it('baseline suppresses existing findings; a new finding still fails the gate', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-base-'));
    dirs.push(dir);
    writeFileSync(
      join(dir, 'app.js'),
      `const express = require('express');\nconst app = express();\napp.get('/c', (req, res) => { eval(req.query.x); });\n`,
    );
    const first = runCli(['scan', dir, '--modules', 'sast', '--update-baseline', '--fail-on', 'high']);
    expect(first.status).toBe(0);
    expect(existsSync(join(dir, '.fullshield-baseline.json'))).toBe(true);

    const second = runCli(['scan', dir, '--modules', 'sast', '--fail-on', 'high']);
    expect(second.status).toBe(0);

    writeFileSync(
      join(dir, 'app.js'),
      `const express = require('express');\nconst app = express();\napp.get('/c', (req, res) => { eval(req.query.x); });\napp.get('/r', (req, res) => { res.redirect(req.query.next); });\n`,
    );
    const third = runCli(['scan', dir, '--modules', 'sast', '--fail-on', 'high', '--json']);
    expect(third.status).toBe(1);
    const report = JSON.parse(third.stdout) as { findings: Array<{ ruleId: string }> };
    expect(report.findings.some((f) => f.ruleId === 'SAST-REDIRECT-001')).toBe(true);
    expect(report.findings.some((f) => f.ruleId === 'SAST-EVAL-001')).toBe(false);
  });

  it('honors // fullshield-ignore RULE: reason on the next line', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-ign-'));
    dirs.push(dir);
    writeFileSync(
      join(dir, 'app.js'),
      `const express = require('express');\nconst app = express();\napp.get('/c', (req, res) => {\n  // fullshield-ignore SAST-EVAL-001: demo only\n  eval(req.query.x);\n});\n`,
    );
    const { status, stdout } = runCli(['scan', dir, '--modules', 'sast', '--fail-on', 'high', '--json']);
    const report = JSON.parse(stdout) as { findings: Array<{ ruleId: string }> };
    expect(report.findings.some((f) => f.ruleId === 'SAST-EVAL-001')).toBe(false);
    expect(status).toBe(0);
  });
});
