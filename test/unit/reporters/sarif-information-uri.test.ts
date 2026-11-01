import { describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { makeFindingId, summarize, type Finding } from '../../../src/core/finding.js';
import { renderSarifReport } from '../../../src/reporters/sarif.js';

function result(): ScanResult {
  const finding: Finding = {
    id: makeFindingId('SAST-SQLI-001', 'src/index.js', 'db.query'),
    ruleId: 'SAST-SQLI-001',
    module: 'sast',
    title: 'SQL injection',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-89',
    file: 'src/index.js',
    line: 1,
    column: 0,
    message: 'Tainted input is concatenated into a SQL query.',
    remediation: 'Use a parameterized query.',
    snippet: 'db.query(a + b)',
  };
  return {
    findings: [finding],
    summary: summarize([finding]),
    metadata: {
      version: '3.5.5',
      startedAt: '2026-11-01T00:00:00.000Z',
      durationMs: 1,
      cwd: '/tmp/app',
      filesScanned: 1,
      modulesRequested: ['sast'],
      modulesRun: ['sast'],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

describe('SARIF informationUri', () => {
  it('names the kathanp/fullshield repository', () => {
    const doc = JSON.parse(renderSarifReport(result())) as {
      runs: Array<{ tool: { driver: { informationUri: string } } }>;
    };
    expect(doc.runs[0]?.tool.driver.informationUri).toBe('https://github.com/kathanp/fullshield');
  });
});
