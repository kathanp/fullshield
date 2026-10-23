import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { FLAG, withPerf } from '../../../src/phases/p450.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const findings = [{ ruleId: 'SAST-SQLI-001' }];
const rows = [
  { phase: 'parse', ms: 2 },
  { phase: 'query', ms: 3 },
];

describe('phase 450', () => {
  it('writes one unreviewed row per phase and leaves findings unchanged', () => {
    process.env[FLAG] = '1';
    const withSide = withPerf(findings, rows, 10, 'perf.json');
    const plain = withPerf(findings, rows, 10, undefined);
    expect(withSide.side?.unreviewed).toBe(true);
    expect(withSide.side?.phases).toHaveLength(rows.length);
    expect(withSide.findings).toEqual(plain.findings);
    expect(JSON.stringify(withSide.findings)).not.toContain('unreviewed');
  });

  it('errors with FS-E when --perf is set and the flag is off', () => {
    const result = withPerf(findings, rows, 10, 'perf.json');
    expect(result.code).toBe('FS-E');
    expect(result.findings).toEqual(findings);
    expect(withPerf(findings, rows, 10, undefined).exitCode).toBe(0);
  });

  it('does not reference the network', () => {
    const src = readFileSync(join(root, 'src/phases/p450.ts'), 'utf8');
    expect(src.includes('node:http')).toBe(false);
    expect(src.includes('node:net')).toBe(false);
  });
});
