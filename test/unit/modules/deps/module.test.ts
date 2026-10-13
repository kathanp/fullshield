import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { minFixedVersion, osvSeverity } from '../../../../src/modules/deps/semver.js';

const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

describe('deps module on fixtures', () => {
  it('detects seeded lodash and minimist vulns plus the expresss typosquat (OSV from fixture cache)', async () => {
    const result = await scan({ cwd: vulnerableApp, modules: ['deps'] });
    const vulns = result.findings.filter((f) => f.ruleId === 'DEPS-VULN-001');
    const packages = vulns.map((f) => f.snippet ?? f.message).join('\n');
    expect(packages).toContain('lodash@4.17.11');
    expect(packages).toContain('minimist@1.2.0');
    expect(vulns.some((f) => f.severity === 'critical')).toBe(true);
    expect(vulns.every((f) => (f.references ?? []).some((r) => r.startsWith('GHSA-') || r.startsWith('CVE-')))).toBe(
      true,
    );

    const squats = result.findings.filter((f) => f.ruleId === 'DEPS-TYPOSQUAT-001');
    expect(squats).toHaveLength(1);
    expect(squats[0]?.severity).toBe('medium');
    expect(squats[0]?.confidence).toBe('low');
    expect(`${squats[0]?.snippet ?? ''} ${squats[0]?.message}`).toMatch(/expresss/);
  });

  it('produces zero deps findings on clean-app (no lockfile, no invented vulns)', async () => {
    const result = await scan({ cwd: cleanApp, modules: ['deps'] });
    expect(result.findings).toEqual([]);
  });
});

describe('OSV helpers (no network)', () => {
  it('maps OSV severity strings onto Finding severities', () => {
    expect(osvSeverity({ database_specific: { severity: 'CRITICAL' } })).toBe('critical');
    expect(osvSeverity({ database_specific: { severity: 'HIGH' } })).toBe('high');
    expect(osvSeverity({ database_specific: { severity: 'MODERATE' } })).toBe('medium');
    expect(osvSeverity({ database_specific: { severity: 'LOW' } })).toBe('low');
    expect(osvSeverity({})).toBe('high');
  });

  it('picks the minimum version that includes every listed fix', () => {
    expect(
      minFixedVersion([
        { ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.12' }] }] },
        { ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] },
      ]),
    ).toBe('4.17.21');
  });
});
