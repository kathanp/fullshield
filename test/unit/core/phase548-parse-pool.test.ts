import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import type { Finding } from '../../../src/core/finding.js';

const vulnerableApp = join(import.meta.dirname, '../../fixtures/vulnerable-app');
const cleanApp = join(import.meta.dirname, '../../fixtures/clean-app');

function stable(findings: readonly Finding[]): string {
  const rows = findings.map((finding) => [finding.ruleId, finding.file ?? '', finding.line ?? 0, finding.severity]);
  rows.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return JSON.stringify(rows);
}

afterEach(() => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_PERF2;
  delete process.env.FULLSHIELD_PARSE_WORKERS;
  delete process.env.FULLSHIELD_PARSE_POOL;
});

describe('phase 548 worker parse pool', () => {
  it('matches finding keys for PARSE_WORKERS 1 and 2 with PERF2 on', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_PERF2 = '1';
    process.env.FULLSHIELD_PARSE_WORKERS = '1';
    const one = await scan({ cwd: vulnerableApp, offline: true });
    process.env.FULLSHIELD_PARSE_WORKERS = '2';
    const two = await scan({ cwd: vulnerableApp, offline: true });
    expect(stable(two.findings)).toBe(stable(one.findings));
    const clean = await scan({ cwd: cleanApp, offline: true });
    expect(clean.findings).toEqual([]);
  });
});
