import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  COMPLIANCE_DISCLAIMER,
  RULE_MAP,
  collectRuleIdsFromSources,
  mappingFor,
  renderCompliance,
} from '../../../src/compliance/index.js';
import { scanIac } from '../../../src/iac/index.js';

const root = process.cwd();
const iacApp = join(root, 'test', 'fixtures', 'iac-app');
const iacClean = join(root, 'test', 'fixtures', 'iac-clean');

function walkSrc(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', 'dist'].includes(entry.name)) continue;
      walkSrc(full, out);
    } else if (entry.isFile() && entry.name.endsWith('.ts') && statSync(full).isFile()) {
      out.push(readFileSync(full, 'utf8'));
    }
  }
  return out;
}

describe('Phase 23 compliance mapping', () => {
  it('maps every shipped rule id to OWASP, CWE, ASVS, and PCI', () => {
    const ids = collectRuleIdsFromSources(walkSrc(join(root, 'src')));
    const mapped = new Set(RULE_MAP.map((r) => r.ruleId));
    const missing = ids.filter((id) => !mapped.has(id));
    expect(missing).toEqual([]);
    for (const row of RULE_MAP) {
      expect(row.owasp.length).toBeGreaterThan(0);
      expect(row.cwe.startsWith('CWE-')).toBe(true);
      expect(row.asvs.length).toBeGreaterThan(0);
      expect(row.pci.toLowerCase()).toMatch(/pci/);
    }
    expect(mappingFor('SAST-SQLI-001')?.cwe).toBe('CWE-89');
  });

  it('states not a certification or audit on every compliance report', () => {
    const text = renderCompliance([{ ruleId: 'SAST-SQLI-001', severity: 'high', file: 'a.js' }], 'pci');
    expect(text).toMatch(/not a certification or audit/i);
    expect(text.indexOf(COMPLIANCE_DISCLAIMER)).toBeGreaterThanOrEqual(0);
    expect(text.lastIndexOf(COMPLIANCE_DISCLAIMER)).toBeGreaterThan(text.indexOf(COMPLIANCE_DISCLAIMER));
  });
});

describe('Phase 23 IaC rules (experimental)', () => {
  it('flags seeded GHA, Terraform, and Kubernetes issues', () => {
    const findings = scanIac(iacApp, { experimental: true });
    const ids = findings.map((f) => f.ruleId);
    expect(ids).toEqual(expect.arrayContaining([
      'IAC-GHA-UNPINNED-001',
      'IAC-GHA-PRTARGET-001',
      'IAC-GHA-PERMS-001',
      'IAC-TF-S3PUBLIC-001',
      'IAC-TF-SGOPEN-001',
      'IAC-TF-UNENCRYPTED-001',
      'IAC-K8S-PRIV-001',
      'IAC-GHA-SECRETLOG-001',
      'IAC-COMPOSE-PRIV-001',
    ]));
  });

  it('does not flag the clean IaC fixture', () => {
    expect(scanIac(iacClean, { experimental: true })).toEqual([]);
  });

  it('is a no-op without experimental', () => {
    expect(scanIac(iacApp)).toEqual([]);
  });
});
