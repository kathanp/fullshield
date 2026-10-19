import { describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { makeFindingId, summarize, type Finding } from '../../../src/core/finding.js';
import { renderConsoleReport } from '../../../src/reporters/console.js';
import { renderJsonReport } from '../../../src/reporters/json.js';

function mkResult(findings: Finding[]): ScanResult {
  return {
    findings,
    summary: summarize(findings),
    metadata: {
      version: '0.1.0',
      startedAt: new Date().toISOString(),
      durationMs: 12.3,
      cwd: '/tmp/app',
      filesScanned: 5,
      modulesRequested: ['deps', 'secrets', 'sast', 'config'],
      modulesRun: [],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

const highFinding: Finding = {
  id: makeFindingId('SAST-SQLI-001', 'src/index.js', 'db.query(a + b)'),
  ruleId: 'SAST-SQLI-001',
  module: 'sast',
  title: 'SQL injection via string concatenation',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-89',
  file: 'src/index.js',
  line: 14,
  message: 'Tainted input is concatenated into a SQL query.',
  remediation: 'Use a parameterized query.',
};

const infoFinding: Finding = {
  id: makeFindingId('CONFIG-SCRIPTS-001', 'package.json', 'postinstall'),
  ruleId: 'CONFIG-SCRIPTS-001',
  module: 'config',
  title: 'Dependency declares install scripts',
  severity: 'info',
  confidence: 'medium',
  file: 'package.json',
  message: 'A dependency declares a postinstall script.',
  remediation: 'Review the script before installing.',
};

describe('renderJsonReport', () => {
  it('emits parseable JSON with findings, summary, and metadata', () => {
    const output = renderJsonReport(mkResult([highFinding]));
    const parsed = JSON.parse(output) as {
      findings: Finding[];
      summary: { total: number };
      metadata: { version: string; modulesRun: string[] };
    };
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]?.ruleId).toBe('SAST-SQLI-001');
    expect(parsed.summary.total).toBe(1);
    expect(parsed.metadata.version).toBe('0.1.0');
    expect(parsed.metadata.modulesRun).toEqual([]);
  });

  it('emits an empty findings array when there are none', () => {
    const parsed = JSON.parse(renderJsonReport(mkResult([]))) as { findings: unknown[] };
    expect(parsed.findings).toEqual([]);
  });
});

describe('renderConsoleReport', () => {
  it('shows a success line when there are no findings', () => {
    const output = renderConsoleReport(mkResult([]));
    expect(output).toContain('No findings');
    expect(output).toContain('FullShield v0.1.0');
    expect(output).toContain('scanned 5 files');
  });

  it('notes requested modules that are not implemented yet', () => {
    const output = renderConsoleReport(mkResult([]));
    expect(output).toContain('not implemented yet');
    expect(output).toContain('deps, secrets, sast, config');
  });

  it('groups findings under severity headers with location and remediation', () => {
    const output = renderConsoleReport(mkResult([highFinding, infoFinding]));
    expect(output).toContain('HIGH (1)');
    expect(output).not.toContain('INFO (1)');
    expect(output).toContain('[SAST-SQLI-001]');
    expect(output).toContain('src/index.js:14');
    expect(output).toContain('Use a parameterized query.');
    expect(output).toContain('2 finding(s)');
    expect(output).toContain('1 more (not directly reachable, or below high confidence) — --all or see JSON');
  });
});
