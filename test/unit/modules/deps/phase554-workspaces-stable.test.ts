import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const app = join(import.meta.dirname, '../../../fixtures/workspaces-app');
const single = join(import.meta.dirname, '../../../fixtures/upgrade-plan-app');
const vulnerable = join(import.meta.dirname, '../../../fixtures/vulnerable-app');
const clean = join(import.meta.dirname, '../../../fixtures/clean-app');

function keys(findings: { ruleId: string; file?: string; line?: number; severity: string }[]): string[] {
  return findings
    .map((finding) => `${finding.ruleId}\t${finding.file ?? ''}\t${finding.line ?? ''}\t${finding.severity}`)
    .sort();
}

describe('phase 554 stable workspace lockfiles', () => {
  afterEach(() => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES;
  });

  it('attributes an advisory to the workspace that locks it without the experimental flag', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES;
    const result = await scan({ cwd: app, modules: ['deps'], offline: true });
    const vuln = result.findings.filter((finding) => finding.ruleId === 'DEPS-VULN-001');
    expect(vuln.map((finding) => finding.file)).toEqual(['packages/vuln/package-lock.json']);
    expect(result.findings.some((finding) => finding.file?.startsWith('packages/clean/'))).toBe(false);
  });

  it('matches the experimental flag on for a multi-workspace tree', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES;
    const off = await scan({ cwd: app, modules: ['deps'], offline: true });
    process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES = '1';
    const on = await scan({ cwd: app, modules: ['deps'], offline: true });
    expect(keys(on.findings)).toEqual(keys(off.findings));
  });

  it('leaves single-package apps identical with the flag unset', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES;
    const a = await scan({ cwd: single, modules: ['deps'], offline: true });
    const b = await scan({ cwd: single, modules: ['deps'], offline: true });
    expect(keys(a.findings)).toEqual(keys(b.findings));
    const vuln = await scan({ cwd: vulnerable, modules: ['deps'], offline: true });
    const again = await scan({ cwd: vulnerable, modules: ['deps'], offline: true });
    expect(keys(vuln.findings)).toEqual(keys(again.findings));
    const cleanResult = await scan({ cwd: clean, modules: ['deps'], offline: true });
    expect(cleanResult.findings.filter((f) => f.severity === 'high' || f.severity === 'critical')).toEqual([]);
  });
});
