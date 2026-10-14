import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');

describe('dependency reachability (Phase 13)', () => {
  it('keeps imported+called lodash critical and downgrades unused lockfile vulns', async () => {
    const result = await scan({ cwd: vulnerableApp, modules: ['deps'] });
    const lodash = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('lodash@'),
    );
    expect(lodash.length).toBeGreaterThan(0);
    expect(lodash.every((f) => f.reachability === 'reachable')).toBe(true);
    expect(lodash.some((f) => f.severity === 'critical')).toBe(true);

    const unused = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && f.reachability === 'not-imported',
    );
    expect(unused.length).toBeGreaterThan(0);
    expect(unused.every((f) => f.severity !== 'critical' && f.severity !== 'high')).toBe(true);
  });
});
