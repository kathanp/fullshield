import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { makeFindingId, summarize, type Finding } from '../../../src/core/finding.js';
import { lineIndependentFingerprint } from '../../../src/core/fingerprint.js';
import { CI_REPORTS_FLAG, ciReportsEnabled } from '../../../src/modules/sast/experimental.js';
import {
  renderGithubAnnotations,
  renderGitlabCodeQuality,
  renderJunitReport,
} from '../../../src/reporters/ci.js';

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

afterEach(async () => {
  delete process.env[CI_REPORTS_FLAG];
  process.exitCode = undefined;
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

function mkResult(findings: Finding[]): ScanResult {
  return {
    findings,
    summary: summarize(findings),
    metadata: {
      version: '0.3.0',
      startedAt: '2026-10-17T00:00:00.000Z',
      durationMs: 4,
      cwd: '/tmp/app',
      filesScanned: 2,
      modulesRequested: ['deps', 'secrets', 'sast', 'config'],
      modulesRun: ['sast', 'config'],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

const highFinding: Finding = {
  id: makeFindingId('SAST-SQLI-001', 'src/index.js', 'db.query(a + b)'),
  ruleId: 'SAST-SQLI-001',
  module: 'sast',
  title: 'SQL injection',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-89',
  file: 'src\\index.js',
  line: 14,
  column: 3,
  message: 'Tainted input is concatenated.\nSee: 100%',
  remediation: 'Use a parameterized query.',
};

const infoFinding: Finding = {
  id: makeFindingId('CONFIG-SCRIPTS-001', 'package.json', 'postinstall'),
  ruleId: 'CONFIG-SCRIPTS-001',
  module: 'config',
  title: 'Install script',
  severity: 'info',
  confidence: 'medium',
  file: 'package.json',
  line: 8,
  message: 'A dependency declares a postinstall script.',
  remediation: 'Review the script before installing.',
};

describe('CI report renderers', () => {
  it('writes GitHub workflow commands with escaped text and posix paths', () => {
    const output = renderGithubAnnotations(mkResult([highFinding, infoFinding]));
    expect(output).toContain(
      '::error file=src/index.js,line=14,col=4,title=SAST-SQLI-001::Tainted input is concatenated.%0ASee%3A 100%25',
    );
    expect(output).toContain('::notice file=package.json,line=8,title=CONFIG-SCRIPTS-001::');
    expect(output).not.toContain('src\\index.js');
  });

  it('writes a notice when there are no findings', () => {
    expect(renderGithubAnnotations(mkResult([]))).toBe('::notice title=FullShield::No findings\n');
  });

  it('writes JUnit failures for medium and above, and skips low and info', () => {
    const xml = renderJunitReport(mkResult([highFinding, infoFinding]));
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    expect(xml).toContain('failures="1"');
    expect(xml).toContain('skipped="1"');
    expect(xml).toContain('<failure type="high"');
    expect(xml).toContain('Tainted input is concatenated.');
    expect(xml).toContain('<skipped');
    expect(xml).toContain('file="src/index.js"');
    expect(xml).not.toContain('<!DOCTYPE');
  });

  it('writes one passing JUnit case when there are no findings', () => {
    const xml = renderJunitReport(mkResult([]));
    expect(xml).toContain('failures="0"');
    expect(xml).toContain('<testcase name="scan" classname="fullshield"/>');
    expect(xml).not.toContain('<failure');
  });

  it('writes GitLab Code Quality JSON with mapped severities', () => {
    const parsed = JSON.parse(renderGitlabCodeQuality(mkResult([highFinding, infoFinding]))) as Array<{
      check_name: string;
      fingerprint: string;
      severity: string;
      location: { path: string; lines?: { begin: number } };
    }>;
    expect(parsed).toHaveLength(2);
    expect(parsed[0]).toMatchObject({
      check_name: 'SAST-SQLI-001',
      fingerprint: lineIndependentFingerprint(highFinding),
      severity: 'critical',
      location: { path: 'src/index.js', lines: { begin: 14 } },
    });
    expect(parsed[1]?.severity).toBe('info');
  });

  it('writes an empty GitLab array when there are no findings', () => {
    expect(renderGitlabCodeQuality(mkResult([]))).toBe('[]\n');
  });
});

describe('scan CI report flags', () => {
  it('refuses the report files unless the experimental flag is set', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-ci-reports-'));
    dirs.push(dir);
    const err: string[] = [];
    const program = createProgram({
      out: () => {},
      err: (text) => err.push(text),
    });
    await program.parseAsync([
      'node',
      'fullshield',
      'scan',
      cleanApp,
      '--offline',
      '--github-annotations',
      join(dir, 'annotations.txt'),
    ]);
    expect(process.exitCode).toBe(2);
    expect(err.join('\n')).toContain('FS-E005');
    expect(err.join('\n')).toContain(CI_REPORTS_FLAG);
    await expect(readFile(join(dir, 'annotations.txt'), 'utf8')).rejects.toThrow();
    expect(ciReportsEnabled()).toBe(false);
  });

  it('writes all three reports when the flag is set and leaves the console scan unchanged', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-ci-reports-'));
    dirs.push(dir);
    const out: string[] = [];
    const program = createProgram({
      out: (text) => out.push(text),
      err: () => {},
    });
    await program.parseAsync([
      'node',
      'fullshield',
      'scan',
      cleanApp,
      '--offline',
      '--experimental-ci-reports',
      '--github-annotations',
      join(dir, 'annotations.txt'),
      '--junit',
      join(dir, 'junit.xml'),
      '--gitlab',
      join(dir, 'gl-code-quality.json'),
    ]);
    expect(process.exitCode).toBeUndefined();
    expect(out.join('\n')).toContain('No findings');
    expect(await readFile(join(dir, 'annotations.txt'), 'utf8')).toContain('::notice title=FullShield::No findings');
    expect(await readFile(join(dir, 'junit.xml'), 'utf8')).toContain('failures="0"');
    expect(await readFile(join(dir, 'gl-code-quality.json'), 'utf8')).toBe('[]\n');
  });
});
