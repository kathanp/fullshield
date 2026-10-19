import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const app = join(import.meta.dirname, '../../../fixtures/validation-app');
const clean = join(import.meta.dirname, '../../../fixtures/clean-app');

function byFile(findings: { ruleId: string; file?: string; snippet?: string }[], ruleId: string, file: string) {
  return findings.filter((finding) => finding.ruleId === ruleId && finding.file?.endsWith(file));
}

describe('phase 53 validation inference', () => {
  afterEach(() => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_VALIDATION;
  });

  it('keeps the NoSQL finding when the flag is off', async () => {
    const result = await scan({ cwd: app, modules: ['sast'] });
    const nosql = byFile(result.findings, 'SAST-NOSQLI-001', 'zod-route.js');
    expect(nosql.some((finding) => finding.snippet?.includes('req.body.name })'))).toBe(true);
    expect(nosql.some((finding) => finding.snippet?.includes('req.body.note'))).toBe(true);
    expect(byFile(result.findings, 'SAST-SQLI-001', 'zod-route.js').length).toBeGreaterThan(0);
  });

  it('clears only a primitive field and still reports SQL and unvalidated fields', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_VALIDATION = '1';
    const result = await scan({ cwd: app, modules: ['sast'] });
    const zod = byFile(result.findings, 'SAST-NOSQLI-001', 'zod-route.js');
    expect(zod.some((finding) => finding.snippet?.includes('req.body.name })'))).toBe(false);
    expect(zod.some((finding) => finding.snippet?.includes('req.body.note'))).toBe(true);
    expect(byFile(result.findings, 'SAST-SQLI-001', 'zod-route.js').length).toBeGreaterThan(0);
    expect(byFile(result.findings, 'SAST-NOSQLI-001', 'joi-route.js')).toEqual([]);
    expect(byFile(result.findings, 'SAST-NOSQLI-001', 'class-route.ts')).toEqual([]);
  });

  it('leaves clean-app at zero with and without the flag', async () => {
    const off = await scan({ cwd: clean, modules: ['sast'] });
    process.env.FULLSHIELD_EXPERIMENTAL_VALIDATION = '1';
    const on = await scan({ cwd: clean, modules: ['sast'] });
    expect(off.findings).toEqual([]);
    expect(on.findings).toEqual([]);
  });
});
