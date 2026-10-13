import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { IMPLEMENTED_MODULES, builtinModules, runScan } from '../../../../src/core/engine.js';

const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

describe('secrets module registration', () => {
  it('is registered as a built-in module from phase 2 on', () => {
    expect(IMPLEMENTED_MODULES).toContain('secrets');
    expect(builtinModules.some((m) => m.name === 'secrets')).toBe(true);
  });
});

describe('secrets module on fixtures', () => {
  it('detects every seeded secret in vulnerable-app', async () => {
    const result = await runScan({ cwd: vulnerableApp, modules: ['secrets'] });
    const ruleIds = new Set(result.findings.map((f) => f.ruleId));
    expect(ruleIds).toContain('SECRET-AWS-001');
    expect(ruleIds).toContain('SECRET-STRIPE-001');
    expect(ruleIds).toContain('SECRET-JWT-001');
    expect(ruleIds).toContain('SECRET-DBURL-001');
    expect(ruleIds).toContain('SECRET-ENVFILE-001');
  });

  it('produces zero findings on clean-app (no false positives)', async () => {
    const result = await runScan({ cwd: cleanApp, modules: ['secrets'] });
    expect(result.findings).toEqual([]);
  });

  it('attributes the seeded code secrets to the right file and masks snippets', async () => {
    const result = await runScan({ cwd: vulnerableApp, modules: ['secrets'] });
    const aws = result.findings.find((f) => f.ruleId === 'SECRET-AWS-001');
    expect(aws?.file).toBe('src/index.js');
    expect(aws?.snippet).toBe('AKIA****');
    const serialized = JSON.stringify(result.findings);
    expect(serialized).not.toContain('AKIA' + 'IOSFODNN7EXAMPLE');
    expect(serialized).not.toContain('fake-password-fixture');
    expect(serialized).not.toContain('sk_test_' + 'FAKEfakeFAKEfakeFAKE1234');
  });

  it('reports at least one high-severity finding so the CI gate engages', async () => {
    const result = await runScan({ cwd: vulnerableApp, modules: ['secrets'] });
    expect(result.summary.bySeverity.high + result.summary.bySeverity.critical).toBeGreaterThan(0);
  });
});
