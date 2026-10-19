import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const app = join(import.meta.dirname, '../../../fixtures/custom-sast-app');

function keys(findings: { ruleId: string; file?: string; line?: number; severity: string }[]): string[] {
  return findings.map((finding) => `${finding.ruleId}\t${finding.file ?? ''}\t${finding.line ?? ''}\t${finding.severity}`).sort();
}

describe('phase 64 config sources and sanitizers', () => {
  afterEach(() => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS;
  });

  it('rejects sast.sources when the flag is off', async () => {
    await expect(scan({ cwd: app, modules: ['sast'] })).rejects.toThrow(/FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS/);
  });

  it('treats a named callee as tainted and clears only the listed class', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS = '1';
    const result = await scan({ cwd: app, modules: ['sast'] });
    const sql = result.findings.filter((finding) => finding.ruleId === 'SAST-SQLI-001');
    expect(sql.some((finding) => finding.snippet?.includes('query(raw)'))).toBe(true);
    expect(sql.some((finding) => finding.snippet?.includes('query(safe)'))).toBe(false);
    expect(result.findings.some((finding) => finding.ruleId === 'SAST-PATH-001')).toBe(true);
  });

  it('keeps the same findings when the config does not declare helpers', async () => {
    const off = await scan({ cwd: app, modules: ['sast'], configPath: join(app, 'plain.config.json') });
    process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS = '1';
    const on = await scan({ cwd: app, modules: ['sast'], configPath: join(app, 'plain.config.json') });
    expect(keys(on.findings)).toEqual(keys(off.findings));
    expect(on.findings.some((finding) => finding.ruleId === 'SAST-SQLI-001' && finding.snippet?.includes('query(safe)'))).toBe(true);
  });
});
