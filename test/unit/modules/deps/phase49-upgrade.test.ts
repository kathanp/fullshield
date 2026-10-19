import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { chooseUpgradePlan } from '../../../../src/modules/deps/upgrade-plan.js';

const planApp = join(import.meta.dirname, '../../../fixtures/upgrade-plan-app');
const noFixApp = join(import.meta.dirname, '../../../fixtures/upgrade-nofix-app');

function keys(findings: { ruleId: string; file?: string; line?: number; severity: string }[]): string[] {
  return findings.map((f) => `${f.ruleId}\t${f.file ?? ''}\t${f.line ?? ''}\t${f.severity}`).sort();
}

describe('phase 49 upgrade plan', () => {
  it('picks the highest OSV fixed version and skips a package with no fix', async () => {
    const result = await scan({ cwd: planApp, modules: ['deps'], offline: true });
    expect(result.metadata.upgradePlan?.bumps).toEqual([
      { name: 'express', from: '4.17.0', to: '4.21.0', safe: true, findings: 2 },
    ]);
    expect(result.metadata.upgradePlan?.unresolved).toEqual(['held']);
    expect(result.metadata.upgradePlan?.sentence).toBe(
      '1 bump (express 4.17.0 → 4.21.0) resolves 2 findings. No fixed version in the OSV cache for held.',
    );
    expect(result.metadata.upgradePlan?.bumps.some((bump) => bump.name === 'minimist')).toBe(false);
    const again = await scan({ cwd: planApp, modules: ['deps'], offline: true });
    expect(keys(again.findings)).toEqual(keys(result.findings));
  });

  it('produces no bump when OSV names no fixed version', async () => {
    const result = await scan({ cwd: noFixApp, modules: ['deps'], offline: true });
    expect(result.metadata.upgradePlan?.bumps).toEqual([]);
    expect(result.metadata.upgradePlan?.sentence).toContain('No fixed version');
  });

  it('breaks ties by fewer bumps, then package name', () => {
    const plan = chooseUpgradePlan([
      { name: 'zzz', from: '1.0.0', id: 'GHSA-same', fixed: '1.1.0' },
      { name: 'aaa', from: '1.0.0', id: 'GHSA-same', fixed: '1.2.0' },
    ]);
    expect(plan?.bumps.map((bump) => bump.name)).toEqual(['aaa']);
  });
});
