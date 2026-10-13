import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/engine.js';

const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

const PHASE4 = [
  'SAST-SQLI-001',
  'SAST-CMDI-001',
  'SAST-PATH-001',
  'SAST-EVAL-001',
  'SAST-JWT-001',
  'SAST-CRYPTO-001',
] as const;

describe('sast engine on fixtures', () => {
  it('detects all six Phase-4 rules in vulnerable-app', async () => {
    const result = await scan({ cwd: vulnerableApp, modules: ['sast'] });
    const ids = new Set(result.findings.map((f) => f.ruleId));
    for (const id of PHASE4) {
      expect(ids, `expected ${id}`).toContain(id);
    }
  });

  it('produces zero sast findings on clean-app (parameterized query, resolve+prefix, execFile, verify, randomUUID)', async () => {
    const result = await scan({ cwd: cleanApp, modules: ['sast'] });
    expect(result.findings).toEqual([]);
  });
});

describe('taint-lite', () => {
  it('propagates taint through assignment and concatenation within a function only', async () => {
    const sameFn = await runSastOnText(
      'a.js',
      `function handler(req) { const id = req.query.id; const sql = 'SELECT ' + id; db.query(sql); }`,
    );
    expect(sameFn.some((f) => f.ruleId === 'SAST-SQLI-001')).toBe(true);

    const otherFn = await runSastOnText(
      'a.js',
      `function source(req) { return req.query.id; }\nfunction sink(id) { db.query('SELECT ' + id); }`,
    );
    expect(otherFn.some((f) => f.ruleId === 'SAST-SQLI-001')).toBe(false);
  });
});
