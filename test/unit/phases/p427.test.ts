import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, renderTrend, type TrendRow } from '../../../src/phases/p427.js';

afterEach(() => {
  delete process.env[FLAG];
});

const rows: TrendRow[] = [{ scanId: 's1', ruleId: 'SAST-SQLI-001', count: 2 }];

describe('phase 427 local trend report', () => {
  it('fails with FS-E when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(renderTrend(rows, { format: 'text', scan: true })).toEqual({
      exitCode: 1,
      code: 'FS-E',
      text: 'FS-E trend is experimental',
      json: null,
      startedScan: false,
    });
  });

  it('prints local counts and records a requested scan', () => {
    process.env[FLAG] = '1';
    const text = renderTrend(rows, { format: 'text' });
    expect(text.exitCode).toBe(0);
    expect(text.startedScan).toBe(false);
    expect(text.text).toBe('local unreviewed counts\ns1 SAST-SQLI-001 2');
    expect(text.text).not.toContain('score');
    const json = renderTrend(rows, { format: 'json', scan: true });
    expect(json.startedScan).toBe(true);
    expect(json.json).toEqual({ header: 'local unreviewed counts', rows, count: 1 });
    expect(json.text).toBe(JSON.stringify(json.json));
  });

  it('prints zero when there are no rows', () => {
    process.env[FLAG] = '1';
    const result = renderTrend([], { format: 'text' });
    expect(result.exitCode).toBe(0);
    expect(result.startedScan).toBe(false);
    expect(result.text).toBe('local unreviewed counts\n0');
  });
});
