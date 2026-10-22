import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p348.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 348', () => {
  it('leaves rows unchanged when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    const row = { packageName: 'fixture-pkg', ruleId: 'DEPS-DEPRECATED-001', severity: 'medium' as const, deprecated: 'see GHSA-0000-0000-0000' };
    expect(phase.linkDeprecations([row], new Map())).toEqual([row]);
  });

  it('links a cached advisory and marks an unknown id unresolved', () => {
    process.env[phase.FLAG] = '1';
    const linked = phase.linkDeprecations(
      [{ packageName: 'fixture-pkg', ruleId: 'DEPS-DEPRECATED-001', severity: 'medium' as const, deprecated: 'see GHSA-0000-0000-0000' }],
      new Map([['fixture-pkg', ['GHSA-0000-0000-0000']]]),
    );
    expect(linked[0]?.linkedAdvisory).toBe('GHSA-0000-0000-0000');
    expect(linked[0]?.severity).toBe('medium');
    expect(linked.map((item) => item.ruleId)).not.toContain('DEPS-VULN-001');
    const missing = phase.linkDeprecations(
      [{ packageName: 'fixture-pkg', ruleId: 'DEPS-DEPRECATED-001', severity: 'medium' as const, deprecated: 'see GHSA-0000-0000-0000' }],
      new Map(),
    );
    expect(missing[0]?.linkedAdvisory).toBe('unresolved');
  });
});
