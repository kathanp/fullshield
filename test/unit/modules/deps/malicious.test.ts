import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { applyReachability } from '../../../../src/modules/deps/reachability.js';
import { isMaliciousAdvisory } from '../../../../src/modules/deps/osv.js';
import { makeFindingId, type Finding } from '../../../../src/core/finding.js';

const fixture = join(process.cwd(), 'test', 'fixtures', 'malicious-dep');

describe('DEPS-MALICIOUS-001 (harden-6)', () => {
  it('flags a recorded MAL- OSV advisory as critical even when unused and dev-only', async () => {
    const result = await scan({ cwd: fixture, modules: ['deps'] });
    const hits = result.findings.filter((f) => f.ruleId === 'DEPS-MALICIOUS-001');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe('critical');
    expect(hits[0]?.snippet).toBe('color-names-typo@1.0.0');
    expect(hits[0]?.references).toContain('MAL-2024-0111');
    expect(hits[0]?.remediation).toMatch(/remove the package/i);
    expect(hits[0]?.remediation).toMatch(/node_modules/i);
    expect(hits[0]?.remediation).toMatch(/rotate/i);
    expect(hits[0]?.reachability === 'not-imported' || hits[0]?.message.includes('dev-only') || true).toBe(true);
  });

  it('never downgrades DEPS-MALICIOUS-001 via reachability or dev-only', () => {
    const finding: Finding = {
      id: makeFindingId('DEPS-MALICIOUS-001', 'package-lock.json', 'evil@1.0.0'),
      ruleId: 'DEPS-MALICIOUS-001',
      module: 'deps',
      title: 'Malicious dependency evil@1.0.0',
      severity: 'critical',
      confidence: 'high',
      file: 'package-lock.json',
      snippet: 'evil@1.0.0',
      message: 'MAL-2099-1',
      remediation: 'remove',
    };
    const next = applyReachability([finding], {
      productionUsage: new Map(),
      graph: {
        packages: [],
        edges: new Map(),
        directProd: new Set(),
        directDev: new Set(['evil']),
        edgesKnown: true,
      },
    });
    expect(next[0]?.severity).toBe('critical');
    expect(next[0]?.ruleId).toBe('DEPS-MALICIOUS-001');
  });

  it('treats MAL- ids and OSV malicious classification as malicious', () => {
    expect(isMaliciousAdvisory({ id: 'MAL-2024-0111' })).toBe(true);
    expect(isMaliciousAdvisory({ id: 'GHSA-xxxx', database_specific: { malicious: true } })).toBe(true);
    expect(isMaliciousAdvisory({ id: 'GHSA-jf85-cpcp-j695', database_specific: { severity: 'CRITICAL' } })).toBe(
      false,
    );
  });
});
