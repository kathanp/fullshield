import { afterEach, describe, expect, it } from 'vitest';

import { DEFAULT_CONFIG } from '../../../src/core/config.js';
import type { ScanResult } from '../../../src/core/engine.js';
import { makeFindingId, summarize, type Finding } from '../../../src/core/finding.js';
import { renderSarifReport, validateSarif21 } from '../../../src/reporters/sarif.js';

function mkResult(findings: Finding[]): ScanResult {
  return {
    findings,
    summary: summarize(findings),
    metadata: {
      version: '0.3.0',
      startedAt: '2026-10-18T00:00:00.000Z',
      durationMs: 1,
      cwd: '/tmp/app',
      filesScanned: 1,
      modulesRequested: ['deps'],
      modulesRun: ['deps'],
    },
    config: structuredClone(DEFAULT_CONFIG),
  };
}

function dep(line: number): Finding {
  return {
    id: makeFindingId('DEPS-VULN-001', 'package-lock.json', 'express@4.17.0'),
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: 'Vulnerable dependency express@4.17.0',
    severity: 'high',
    confidence: 'high',
    file: 'package-lock.json',
    line,
    message: 'express@4.17.0 has a known vulnerability.',
    remediation: 'Upgrade express.',
    snippet: 'express@4.17.0',
    reachability: 'reachable-via-dependency',
    dependencyPath: ['app', 'express'],
    trace: [{ file: 'src/index.js', line: 2, note: 'import' }],
  };
}

describe('phase 74 SARIF v2 fields', () => {
  afterEach(() => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_SARIF_V2;
  });

  it('keeps default SARIF byte-identical when the flag is off', () => {
    const first = renderSarifReport(mkResult([dep(10)]));
    const second = renderSarifReport(mkResult([dep(10)]));
    expect(second).toBe(first);
    expect(first.includes('fullshield/v1')).toBe(false);
    expect(first.includes('unreviewed')).toBe(false);
    expect(validateSarif21(JSON.parse(first))).toEqual([]);
  });

  it('keeps the fingerprint when the line shifts by 3', () => {
    process.env.FULLSHIELD_EXPERIMENTAL_SARIF_V2 = '1';
    const before = JSON.parse(renderSarifReport(mkResult([dep(10)]))) as {
      runs: Array<{
        tool: { driver: { rules: Array<{ help?: { markdown: string }; properties?: { precision: string } }> } };
        results: Array<{
          partialFingerprints: { 'fullshield/v1': string };
          relatedLocations?: Array<{ message: { text: string } }>;
          properties?: { reachability: string };
          codeFlows?: unknown[];
        }>;
      }>;
    };
    const after = JSON.parse(renderSarifReport(mkResult([dep(13)]))) as typeof before;
    expect(validateSarif21(before)).toEqual([]);
    expect(after.runs[0]?.results[0]?.partialFingerprints['fullshield/v1']).toBe(
      before.runs[0]?.results[0]?.partialFingerprints['fullshield/v1'],
    );
    expect(before.runs[0]?.tool.driver.rules[0]?.properties?.precision).toBe('unreviewed');
    expect(before.runs[0]?.tool.driver.rules[0]?.help?.markdown.length).toBeGreaterThan(0);
    expect(before.runs[0]?.tool.driver.rules[0]?.help?.markdown.length).toBeLessThanOrEqual(2048);
    expect(before.runs[0]?.results[0]?.properties?.reachability).toBe('reachable-via-dependency');
    expect(before.runs[0]?.results[0]?.relatedLocations?.map((loc) => loc.message.text)).toEqual(['app', 'express']);
    expect(before.runs[0]?.results[0]?.codeFlows).toBeDefined();
  });
});
