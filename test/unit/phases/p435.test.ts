import { afterEach, describe, expect, it } from 'vitest';

import { BANNED_WORDS, enabled, FLAG, SUMMARY_TEMPLATE, summarize, type SummaryFinding } from '../../../src/phases/p435.js';

afterEach(() => {
  delete process.env[FLAG];
});

const findings: SummaryFinding[] = [
  { severity: 'high', module: 'sast', ruleId: 'A' },
  { severity: 'high', module: 'sast', ruleId: 'A' },
  { severity: 'low', module: 'deps', ruleId: 'B' },
];

describe('phase 435 summary page', () => {
  it('errors with FS-E when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(summarize(findings)).toEqual({
      exitCode: 1,
      code: 'FS-E',
      text: 'FS-E summary is experimental',
      json: null,
      scanned: false,
    });
  });

  it('counts severity, module, and rules without a score', () => {
    process.env[FLAG] = '1';
    const result = summarize(findings);
    expect(result.exitCode).toBe(0);
    expect(result.scanned).toBe(false);
    expect(result.text.startsWith(SUMMARY_TEMPLATE)).toBe(true);
    expect(result.text).toContain('severity {"high":2,"low":1}');
    expect(result.text).toContain('module {"sast":2,"deps":1}');
    expect(result.text).toContain('by count A 2, B 1');
    expect(result.json).toEqual({
      unreviewed: true,
      bySeverity: { high: 2, low: 1 },
      byModule: { sast: 2, deps: 1 },
      topByCount: [
        { ruleId: 'A', count: 2 },
        { ruleId: 'B', count: 1 },
      ],
      total: 3,
    });
    for (const word of BANNED_WORDS) {
      expect(result.text.toLowerCase()).not.toContain(word);
    }
  });

  it('stays at zero findings and marks a reviewed row', () => {
    process.env[FLAG] = '1';
    const empty = summarize(null);
    expect(empty.exitCode).toBe(0);
    expect(empty.scanned).toBe(false);
    expect(empty.json).toMatchObject({ total: 0, unreviewed: true });
    expect(empty.text).toContain('severity {}');
    const reviewed = summarize([{ severity: 'high', module: 'sast', ruleId: 'A', reviewed: true }]);
    expect(reviewed.json).toMatchObject({ unreviewed: false, total: 1 });
    expect(reviewed.scanned).toBe(false);
  });
});
