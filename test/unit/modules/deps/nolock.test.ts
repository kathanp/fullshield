import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const noLockApp = join(process.cwd(), 'test', 'fixtures', 'no-lock-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

describe('DEPS-NOLOCK-001', () => {
  it('emits an info finding and still checks exact package.json pins', async () => {
    const result = await scan({ cwd: noLockApp, modules: ['deps'] });
    const nolock = result.findings.filter((f) => f.ruleId === 'DEPS-NOLOCK-001');
    expect(nolock).toHaveLength(1);
    expect(nolock[0]?.severity).toBe('info');
    expect(nolock[0]?.file).toBe('package.json');
    expect(nolock[0]?.message).toContain('No lockfile found');
    expect(nolock[0]?.message).toContain('dependency vulnerabilities were not checked');

    const vulns = result.findings.filter((f) => f.ruleId === 'DEPS-VULN-001');
    expect(vulns.some((f) => (f.snippet ?? '').includes('lodash@4.17.11'))).toBe(true);
    expect(vulns.every((f) => !(f.snippet ?? '').includes('express@'))).toBe(true);
  });

  it('does not emit DEPS-NOLOCK-001 when a lockfile is present', async () => {
    const result = await scan({ cwd: cleanApp, modules: ['deps'] });
    expect(result.findings.filter((f) => f.ruleId === 'DEPS-NOLOCK-001')).toEqual([]);
  });
});
