import { describe, expect, it } from 'vitest';

import {
  SEVERITIES,
  failsCi,
  isModuleName,
  isSeverity,
  makeFindingId,
  meetsThreshold,
  severityRank,
  sortFindings,
  summarize,
  type Finding,
} from '../../../src/core/finding.js';

function mkFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id ?? makeFindingId(overrides.ruleId ?? 'TEST-001', overrides.file, overrides.snippet),
    ruleId: 'TEST-001',
    module: 'sast',
    title: 'Test finding',
    severity: 'medium',
    confidence: 'high',
    message: 'something is wrong',
    remediation: 'fix it',
    ...overrides,
  };
}

describe('severity utilities', () => {
  it('orders severities info < low < medium < high < critical', () => {
    expect(SEVERITIES).toEqual(['info', 'low', 'medium', 'high', 'critical']);
    expect(severityRank('info')).toBeLessThan(severityRank('low'));
    expect(severityRank('low')).toBeLessThan(severityRank('medium'));
    expect(severityRank('medium')).toBeLessThan(severityRank('high'));
    expect(severityRank('high')).toBeLessThan(severityRank('critical'));
  });

  it('meetsThreshold is true at or above the threshold only', () => {
    expect(meetsThreshold('high', 'high')).toBe(true);
    expect(meetsThreshold('critical', 'high')).toBe(true);
    expect(meetsThreshold('medium', 'high')).toBe(false);
    expect(meetsThreshold('info', 'low')).toBe(false);
    expect(meetsThreshold('low', 'info')).toBe(true);
  });

  it('failsCi ignores source:ai even when severity is high', () => {
    expect(failsCi(mkFinding({ severity: 'high' }), 'high')).toBe(true);
    expect(failsCi(mkFinding({ severity: 'high', source: 'ai' }), 'high')).toBe(false);
    expect(failsCi(mkFinding({ severity: 'medium', source: 'deterministic' }), 'high')).toBe(false);
  });

  it('validates severity and module names', () => {
    expect(isSeverity('high')).toBe(true);
    expect(isSeverity('severe')).toBe(false);
    expect(isModuleName('secrets')).toBe(true);
    expect(isModuleName('magic')).toBe(false);
  });
});

describe('makeFindingId', () => {
  it('is stable for identical inputs', () => {
    expect(makeFindingId('SAST-SQLI-001', 'src/a.ts', 'db.query(x)')).toBe(
      makeFindingId('SAST-SQLI-001', 'src/a.ts', 'db.query(x)'),
    );
  });

  it('normalizes whitespace in the snippet', () => {
    expect(makeFindingId('R', 'f.ts', 'a  +   b')).toBe(makeFindingId('R', 'f.ts', ' a + b '));
  });

  it('differs when ruleId, file, or snippet differ', () => {
    const base = makeFindingId('R1', 'f.ts', 'x');
    expect(makeFindingId('R2', 'f.ts', 'x')).not.toBe(base);
    expect(makeFindingId('R1', 'g.ts', 'x')).not.toBe(base);
    expect(makeFindingId('R1', 'f.ts', 'y')).not.toBe(base);
  });

  it('is a 16-char hex string and handles missing file/snippet', () => {
    expect(makeFindingId('R1', undefined, undefined)).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('sortFindings', () => {
  it('sorts by severity desc, then file, then line', () => {
    const sorted = sortFindings([
      mkFinding({ id: 'a', severity: 'low', file: 'b.ts', line: 1 }),
      mkFinding({ id: 'b', severity: 'critical', file: 'z.ts', line: 9 }),
      mkFinding({ id: 'c', severity: 'high', file: 'a.ts', line: 5 }),
      mkFinding({ id: 'd', severity: 'high', file: 'a.ts', line: 2 }),
    ]);
    expect(sorted.map((f) => f.id)).toEqual(['b', 'd', 'c', 'a']);
  });

  it('does not mutate the input array', () => {
    const input = [mkFinding({ id: 'a', severity: 'low' }), mkFinding({ id: 'b', severity: 'high' })];
    sortFindings(input);
    expect(input.map((f) => f.id)).toEqual(['a', 'b']);
  });
});

describe('summarize', () => {
  it('counts findings by severity', () => {
    const summary = summarize([
      mkFinding({ severity: 'high' }),
      mkFinding({ severity: 'high' }),
      mkFinding({ severity: 'info' }),
    ]);
    expect(summary.total).toBe(3);
    expect(summary.bySeverity).toEqual({ info: 1, low: 0, medium: 0, high: 2, critical: 0 });
  });

  it('returns zero counts for an empty list', () => {
    const summary = summarize([]);
    expect(summary.total).toBe(0);
    expect(Object.values(summary.bySeverity).every((n) => n === 0)).toBe(true);
  });
});
