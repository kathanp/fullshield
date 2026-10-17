import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

describe('cross-file taint (Phase 13)', () => {
  it('traces tainted input across 3 files to a SQL sink', async () => {
    const result = await scan({ cwd: vulnerableApp, modules: ['sast'] });
    const hits = result.findings.filter(
      (f) => f.ruleId === 'SAST-SQLI-001' && f.file === 'src/data/alloc-dao.js',
    );
    expect(hits.length).toBeGreaterThan(0);
    const trace = hits[0]?.trace ?? [];
    const files = new Set(trace.map((s) => s.file));
    expect(files.has('src/routes/alloc.js')).toBe(true);
    expect(files.has('src/services/alloc.js')).toBe(true);
    expect(files.has('src/data/alloc-dao.js')).toBe(true);
    expect(files.size).toBeGreaterThanOrEqual(3);
  });

  it('does not flag the parameterized 3-file chain on clean-app', async () => {
    const result = await scan({ cwd: cleanApp, modules: ['sast'] });
    expect(result.findings.filter((f) => f.file?.includes('alloc'))).toEqual([]);
  });

  it('keeps the same cross-file SQL trace when files are parsed one at a time', async () => {
    process.env.FULLSHIELD_SAST_STREAM_AT = '1';
    try {
      const result = await scan({ cwd: vulnerableApp, modules: ['sast'] });
      const hits = result.findings.filter(
        (f) => f.ruleId === 'SAST-SQLI-001' && f.file === 'src/data/alloc-dao.js',
      );
      expect(hits.length).toBeGreaterThan(0);
      const files = new Set((hits[0]?.trace ?? []).map((s) => s.file));
      expect(files.has('src/routes/alloc.js')).toBe(true);
      expect(files.has('src/services/alloc.js')).toBe(true);
      expect(files.has('src/data/alloc-dao.js')).toBe(true);
    } finally {
      delete process.env.FULLSHIELD_SAST_STREAM_AT;
    }
  });

  it('returns the same cross-file SQL trace when the parse pool caches the tree', async () => {
    process.env.FULLSHIELD_PARSE_POOL = '1';
    try {
      const first = await scan({ cwd: vulnerableApp, modules: ['sast'] });
      const second = await scan({ cwd: vulnerableApp, modules: ['sast'] });
      const pick = (findings: typeof first.findings): string[] =>
        findings
          .filter((f) => f.ruleId === 'SAST-SQLI-001' && f.file === 'src/data/alloc-dao.js')
          .map((f) => `${f.line ?? 0}:${(f.trace ?? []).map((step) => step.file).join(',')}`);
      const left = pick(first.findings);
      expect(left.length).toBeGreaterThan(0);
      expect(pick(second.findings)).toEqual(left);
    } finally {
      delete process.env.FULLSHIELD_PARSE_POOL;
    }
  });
});
