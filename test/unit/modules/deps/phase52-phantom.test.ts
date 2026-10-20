import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

describe('phase 52 phantom and lock mismatch', () => {
  it('reports a phantom import and a lockfile range mismatch, and not builtins', async () => {
    const result = await scan({ cwd: join(import.meta.dirname, '../../../fixtures/phantom-app'), modules: ['deps'], offline: true });
    expect(result.findings.some((finding) => finding.ruleId === 'DEPS-PHANTOM-001' && finding.snippet === 'missing-pkg')).toBe(
      true,
    );
    expect(result.findings.some((finding) => finding.ruleId === 'DEPS-PHANTOM-001' && finding.snippet === 'fs')).toBe(false);
    expect(result.findings.some((finding) => finding.ruleId === 'DEPS-PHANTOM-001' && finding.snippet === 'express')).toBe(
      false,
    );
    expect(result.findings.some((finding) => finding.ruleId === 'DEPS-LOCKMISMATCH-001' && finding.snippet === 'left-pad@2.0.0')).toBe(
      true,
    );
    const phantom = result.findings.find((finding) => finding.ruleId === 'DEPS-PHANTOM-001' && finding.snippet === 'missing-pkg');
    const mismatch = result.findings.find((finding) => finding.ruleId === 'DEPS-LOCKMISMATCH-001');
    expect(phantom?.line).toBe(4);
    expect(mismatch?.line).toBe(4);
    expect(result.findings.some((finding) => finding.snippet === 'dev-only-pkg')).toBe(false);
    const keys = result.findings
      .filter((finding) => finding.ruleId === 'DEPS-PHANTOM-001' || finding.ruleId === 'DEPS-LOCKMISMATCH-001')
      .map((finding) => `${finding.ruleId}\t${finding.file}\t${finding.line}\t${finding.severity}`);
    expect(keys.every((key) => !key.includes('\tundefined\t'))).toBe(true);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('reports an undeclared import under scripts/ as low and keeps a src import medium', async () => {
    const result = await scan({ cwd: join(import.meta.dirname, '../../../fixtures/phantom-app'), modules: ['deps'], offline: true });
    const script = result.findings.find(
      (finding) => finding.ruleId === 'DEPS-PHANTOM-001' && finding.file?.endsWith('scripts/undeclared.js') === true,
    );
    const src = result.findings.find((finding) => finding.ruleId === 'DEPS-PHANTOM-001' && finding.snippet === 'missing-pkg');
    expect(script?.severity).toBe('low');
    expect(src?.severity).toBe('medium');
  });
});
