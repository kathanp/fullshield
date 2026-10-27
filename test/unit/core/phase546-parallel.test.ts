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
});

describe('phase 546 module parallelism on every scan', () => {
  it('keeps vulnerable-app and clean-app finding keys stable across two default scans', async () => {
    const first = await scan({ cwd: vulnerableApp, offline: true });
    const second = await scan({ cwd: vulnerableApp, offline: true });
    expect(stable(second.findings)).toBe(stable(first.findings));
    const clean = await scan({ cwd: cleanApp, offline: true });
    expect(clean.findings.filter((finding) => finding.severity === 'high' || finding.severity === 'critical')).toEqual([]);
  });
});
