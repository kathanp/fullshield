import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const root = join(import.meta.dirname, '../../../fixtures');

describe('phases 50, 51, 52, and 75', () => {
  it('flags swig mustache, stays quiet for handlebars and unknown html, and leaves clean-app at 0', async () => {
    const swig = await scan({ cwd: join(root, 'swig-app'), modules: ['sast'], offline: true });
    expect(swig.findings.some((finding) => finding.ruleId === 'SAST-XSS-001' && finding.file?.endsWith('.swig'))).toBe(
      true,
    );
    const hbs = await scan({ cwd: join(root, 'hbs-app'), modules: ['sast'], offline: true });
    expect(hbs.findings.some((finding) => finding.ruleId === 'SAST-XSS-001')).toBe(false);
    const html = await scan({ cwd: join(root, 'html-app'), modules: ['sast'], offline: true });
    expect(html.findings.some((finding) => finding.ruleId === 'SAST-XSS-001')).toBe(false);
    const clean = await scan({ cwd: join(root, 'clean-app'), modules: ['sast', 'deps'], offline: true });
    expect(clean.findings.filter((finding) => finding.module === 'sast')).toEqual([]);
    expect(clean.findings.some((finding) => finding.ruleId === 'DEPS-PHANTOM-001' || finding.ruleId === 'DEPS-LOCKMISMATCH-001')).toBe(
      false,
    );
  });

  it('follows a SQL string and a Mongo filter returned from another file, not a literal', async () => {
    const result = await scan({ cwd: join(root, 'cross-file-app'), modules: ['sast'], offline: true });
    const sql = result.findings.filter((finding) => finding.ruleId === 'SAST-SQLI-001');
    const nosql = result.findings.filter((finding) => finding.ruleId === 'SAST-NOSQLI-001');
    expect(sql.some((finding) => finding.file === 'src/sql-app.js' && finding.trace?.some((step) => step.file === 'src/sql-lib.js'))).toBe(
      true,
    );
    expect(sql.some((finding) => finding.snippet?.includes('literal'))).toBe(false);
    expect(nosql.some((finding) => finding.file === 'src/nosql-app.js' && finding.trace?.some((step) => step.file === 'src/nosql-lib.js'))).toBe(
      true,
    );
  });

  it('reports a phantom import and a lockfile range mismatch, and not builtins', async () => {
    const result = await scan({ cwd: join(root, 'phantom-app'), modules: ['deps'], offline: true });
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
  });

  it('keeps a route flagged when auth is mounted after it, and clears router-level and prefixed mounts', async () => {
    const result = await scan({ cwd: join(root, 'auth-inherit-app'), modules: ['sast'], offline: true });
    const auth = result.findings.filter((finding) => finding.ruleId === 'SAST-AUTH-001');
    expect(auth.some((finding) => finding.file === 'src/late.js')).toBe(true);
    expect(auth.some((finding) => finding.file === 'src/early.js')).toBe(false);
    expect(auth.some((finding) => finding.file === 'src/api.js')).toBe(false);
  });
});
