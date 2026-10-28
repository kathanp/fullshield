import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const app = join(import.meta.dirname, '../../../fixtures/workspaces-app');
const single = join(import.meta.dirname, '../../../fixtures/upgrade-plan-app');

function keys(findings: { ruleId: string; file?: string; line?: number; severity: string }[]): string[] {
  return findings.map((finding) => `${finding.ruleId}\t${finding.file ?? ''}\t${finding.line ?? ''}\t${finding.severity}`).sort();
}

describe('phase 54 workspace lockfiles', () => {
  afterEach(() => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES;
  });

  it('attributes an advisory to the workspace that locks it', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES = '1';
    const result = await scan({ cwd: app, modules: ['deps'], offline: true });
    const vuln = result.findings.filter((finding) => finding.ruleId === 'DEPS-VULN-001');
    expect(vuln.map((finding) => finding.file)).toEqual(['packages/vuln/package-lock.json']);
    expect(vuln.every((finding) => finding.snippet?.startsWith('express@'))).toBe(true);
    expect(result.findings.some((finding) => finding.file?.startsWith('packages/clean/'))).toBe(false);
  });

  it('leaves a single-package app unchanged when the flag is on', async () => {
    const off = await scan({ cwd: single, modules: ['deps'], offline: true });
    process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES = '1';
    const on = await scan({ cwd: single, modules: ['deps'], offline: true });
    expect(keys(on.findings)).toEqual(keys(off.findings));
  });

  it('reads workspace lockfiles by default on multi-workspace trees (phase 554)', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES;
    const result = await scan({ cwd: app, modules: ['deps'], offline: true });
    expect(result.findings.some((finding) => finding.ruleId === 'DEPS-VULN-001')).toBe(true);
    expect(result.findings.some((finding) => finding.file === 'packages/vuln/package-lock.json')).toBe(
      true,
    );
  });
});
