import { describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { makeFindingId, summarize, type Finding } from '../../../src/core/finding.js';
import { renderHtmlReport } from '../../../src/reporters/html.js';
import { renderMarkdownReport } from '../../../src/reporters/markdown.js';
import { renderSarifReport, validateSarif21 } from '../../../src/reporters/sarif.js';

function mkResult(findings: Finding[]): ScanResult {
  return {
    findings,
    summary: summarize(findings),
    metadata: {
      version: '0.1.0',
      startedAt: '2026-10-13T00:00:00.000Z',
      durationMs: 12.3,
      cwd: '/tmp/app',
      filesScanned: 5,
      modulesRequested: ['sast'],
      modulesRun: ['sast'],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

const finding: Finding = {
  id: makeFindingId('SAST-SQLI-001', 'src/index.js', 'db.query'),
  ruleId: 'SAST-SQLI-001',
  module: 'sast',
  title: 'SQL injection via string concatenation',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-89',
  file: 'src/index.js',
  line: 14,
  column: 3,
  message: 'Tainted input is concatenated into a SQL query.',
  remediation: 'Use a parameterized query.',
  snippet: 'db.query(a + b)',
};

describe('SARIF 2.1.0 reporter', () => {
  it('emits a document that validates against the SARIF 2.1.0 schema', () => {
    const doc = JSON.parse(renderSarifReport(mkResult([finding]))) as unknown;
    expect(validateSarif21(doc)).toEqual([]);
    const sarif = doc as {
      version: string;
      runs: Array<{
        tool: { driver: { name: string; rules: Array<{ id: string }> } };
        results: Array<{ ruleId: string; level: string; message: { text: string } }>;
      }>;
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.name).toBe('FullShield');
    expect(sarif.runs[0]?.tool.driver.rules.some((r) => r.id === 'SAST-SQLI-001')).toBe(true);
    expect(sarif.runs[0]?.results[0]?.ruleId).toBe('SAST-SQLI-001');
    expect(sarif.runs[0]?.results[0]?.level).toBe('error');
    expect(sarif.runs[0]?.results[0]?.message.text).toContain('Tainted input');
  });

  it('maps severity to SARIF level and omits location when file is missing', () => {
    const medium: Finding = { ...finding, id: 'm', severity: 'medium', file: undefined, line: undefined };
    const info: Finding = { ...finding, id: 'i', ruleId: 'DEPS-NOLOCK-001', severity: 'info', column: 0 };
    const doc = JSON.parse(renderSarifReport(mkResult([finding, medium, info]))) as {
      runs: Array<{ results: Array<{ level: string; locations: unknown[] }> }>;
    };
    expect(doc.runs[0]?.results[0]?.level).toBe('error');
    expect(doc.runs[0]?.results[1]?.level).toBe('warning');
    expect(doc.runs[0]?.results[2]?.level).toBe('note');
    expect(doc.runs[0]?.results[1]?.locations).toEqual([]);
  });

  it('rejects a document that is not SARIF 2.1.0', () => {
    expect(validateSarif21(null)).toEqual(['SARIF document must be an object']);
    expect(validateSarif21([])).toEqual(['SARIF document must be an object']);
    expect(validateSarif21({ version: '2.0.0', runs: [] }).length).toBeGreaterThan(0);
    expect(validateSarif21({ version: '2.1.0' })).toEqual(['runs must be an array']);
    expect(validateSarif21({ version: '2.1.0', runs: [null] })).toContain('runs[0] must be an object');
    expect(validateSarif21({ version: '2.1.0', runs: [{ tool: {}, results: [] }] })).toContain(
      'runs[0].tool.driver.name is required',
    );
    expect(validateSarif21({ version: '2.1.0', runs: [{ tool: { driver: { name: 'X' } } }] })).toContain(
      'runs[0].results must be an array',
    );
    expect(
      validateSarif21({
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'X' } }, results: [null] }],
      }),
    ).toContain('runs[0].results[0] must be an object');
    expect(
      validateSarif21({
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'X' } }, results: [{ message: {} }] }],
      }),
    ).toContain('runs[0].results[0].message.text or message.id is required');
    expect(
      validateSarif21({
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'X' } }, results: [{ message: { id: 'm1' } }] }],
      }),
    ).toEqual([]);
  });
});

describe('Markdown reporter', () => {
  it('groups findings by severity with file:line and a one-line fix', () => {
    const md = renderMarkdownReport(mkResult([finding]));
    expect(md).toContain('# FullShield report');
    expect(md).toContain('SAST-SQLI-001');
    expect(md).toContain('src/index.js:14');
    expect(md).toContain('Use a parameterized query.');
    expect(md).toContain('high');
  });
});

describe('HTML reporter', () => {
  it('emits a standalone HTML document that escapes finding text', () => {
    const xss: Finding = {
      ...finding,
      id: 'x',
      message: '<script>alert(1)</script>',
      title: 't < b',
    };
    const html = renderHtmlReport(mkResult([xss]));
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('SAST-SQLI-001');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });
});
