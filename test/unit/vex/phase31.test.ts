import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { makeFindingId, type Finding } from '../../../src/core/finding.js';
import { openHistory, recordProvenance, listProvenance } from '../../../src/dashboard/index.js';
import {
  buildCycloneDxVex,
  buildOpenVex,
  buildVex,
  validateCycloneDxVex,
  validateOpenVex,
} from '../../../src/vex/index.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_VEX';
const vexApp = join(process.cwd(), 'test', 'fixtures', 'vex-app');
const dirs: string[] = [];

beforeEach(() => {
  delete process.env[FLAG];
});

afterEach(() => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function finding(
  snippet: string,
  reachability: Finding['reachability'],
  id = 'CVE-2020-0001',
): Finding {
  return {
    id: makeFindingId('DEPS-VULN-001', 'package-lock.json', snippet),
    ruleId: 'DEPS-VULN-001',
    module: 'deps',
    title: snippet,
    severity: 'high',
    confidence: 'high',
    file: 'package-lock.json',
    snippet,
    message: `${snippet} is affected by ${id}`,
    remediation: 'upgrade',
    references: [id],
    reachability,
  };
}

describe('Phase 31 VEX (experimental)', () => {
  it('emits not_affected + vulnerable_code_not_in_execute_path only for not-imported', () => {
    const doc = buildOpenVex([finding('unused-leaf@1.0.0', 'not-imported', 'CVE-2020-0003')]);
    expect(validateOpenVex(doc)).toEqual([]);
    const stmt = (doc as { statements: Array<Record<string, unknown>> }).statements[0];
    expect(stmt?.status).toBe('not_affected');
    expect(stmt?.justification).toBe('vulnerable_code_not_in_execute_path');
  });

  it('emits under_investigation for reachable, imported-not-called, via-dep, unknown, and missing', () => {
    const kinds: Array<Finding['reachability'] | undefined> = [
      'reachable',
      'imported-not-called',
      'reachable-via-dependency',
      'reachability-unknown',
      undefined,
    ];
    for (const reachability of kinds) {
      const doc = buildOpenVex([finding('called-leaf@1.0.0', reachability, 'CVE-2020-0002')]);
      const stmt = (doc as { statements: Array<{ status: string; justification?: string }> })
        .statements[0];
      expect(stmt?.status).toBe('under_investigation');
      expect(stmt?.justification).toBeUndefined();
    }
  });

  it('never guesses not_affected on CycloneDX VEX either', () => {
    const doc = buildCycloneDxVex(
      { name: 'app', version: '1.0.0' },
      [
        finding('unused-leaf@1.0.0', 'not-imported', 'CVE-2020-0003'),
        finding('called-leaf@1.0.0', 'reachable', 'CVE-2020-0002'),
      ],
    );
    expect(validateCycloneDxVex(doc)).toEqual([]);
    const vulns = (
      doc as {
        vulnerabilities: Array<{ analysis: { state: string; justification?: string } }>;
      }
    ).vulnerabilities;
    const unused = vulns.find((v) => v.analysis.state === 'not_affected');
    expect(unused?.analysis.justification).toBe('code_not_reachable');
    expect(vulns.filter((v) => v.analysis.state === 'not_affected')).toHaveLength(1);
    expect(vulns.some((v) => v.analysis.state === 'in_triage')).toBe(true);
  });

  it('rejects documents that claim not_affected without the execute-path justification', () => {
    expect(
      validateOpenVex({
        '@context': 'https://openvex.dev/ns/v0.2.0',
        '@id': 'https://example.invalid/vex',
        author: 'FullShield',
        timestamp: '2026-10-15T00:00:00Z',
        version: 1,
        statements: [{ vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'pkg:npm/x@1' }], status: 'not_affected' }],
      }).length,
    ).toBeGreaterThan(0);
    expect(
      validateCycloneDxVex({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        components: [],
        vulnerabilities: [{ analysis: { state: 'not_affected' } }],
      }).length,
    ).toBeGreaterThan(0);
  });

  it('builds OpenVEX and CycloneDX from a real reachability scan', async () => {
    const result = await scan({ cwd: vexApp, modules: ['deps'], offline: true });
    const unused = result.findings.find((f) => (f.snippet ?? '').startsWith('unused-leaf@'));
    const called = result.findings.find((f) => (f.snippet ?? '').startsWith('called-leaf@'));
    expect(unused?.reachability).toBe('not-imported');
    expect(called?.reachability).toBe('reachable');

    const open = buildVex(result.findings, 'openvex');
    const cdx = buildVex(result.findings, 'cyclonedx', { name: 'vex-app-fixture', version: '1.0.0' });
    expect(validateOpenVex(open)).toEqual([]);
    expect(validateCycloneDxVex(cdx)).toEqual([]);
  });

  it('records provenance coverage over time in the history DB', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-prov-hist-'));
    dirs.push(dir);
    const db = openHistory(dir);
    try {
      recordProvenance(db, {
        scannedAt: '2026-10-14T00:00:00Z',
        percent: 25,
        withProvenance: 1,
        total: 4,
      });
      recordProvenance(db, {
        scannedAt: '2026-10-15T00:00:00Z',
        percent: 50,
        withProvenance: 2,
        total: 4,
      });
      const rows = listProvenance(db);
      expect(rows).toHaveLength(2);
      expect(rows[1]?.percent).toBe(50);
    } finally {
      db.close();
    }
  });
});
