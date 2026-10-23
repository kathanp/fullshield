import { afterEach, describe, expect, it } from 'vitest';

import { applySla, enabled, FLAG, FsError, loadSlaPolicy, SLA_RULE_ID, type HistoryAge, type SlaFinding } from '../../../src/phases/p445.js';

afterEach(() => {
  delete process.env[FLAG];
});

function finding(over: Partial<SlaFinding> = {}): SlaFinding {
  return {
    ruleId: 'SAST-SQLI-001',
    file: 'src/a.js',
    line: 3,
    severity: 'high',
    module: 'sast',
    fingerprint: 'fp-1',
    message: 'sink',
    ...over,
  };
}

const policy = { high: 7 };
const scanTime = '2026-10-22';

describe('phase 445 fix-by dates', () => {
  it('does not emit POLICY-SLA-001 when the flag is off', () => {
    expect(enabled()).toBe(false);
    const rows = [finding()];
    const history: HistoryAge[] = [{ fingerprint: 'fp-1', firstSeen: '2026-01-01' }];
    const result = applySla(rows, policy, history, scanTime);
    expect(result).toEqual(rows);
    expect(result.some((row) => row.ruleId === SLA_RULE_ID)).toBe(false);
    expect(result[0]?.severity).toBe('high');
  });

  it('emits an info row when the finding is past the day count', () => {
    process.env[FLAG] = '1';
    const rows = [finding()];
    const history: HistoryAge[] = [{ fingerprint: 'fp-1', firstSeen: '2026-01-01' }];
    const result = applySla(rows, loadSlaPolicy(policy), history, scanTime);
    expect(result[0]).toBe(rows[0]);
    expect(result[0]?.severity).toBe('high');
    expect(result[1]).toMatchObject({
      ruleId: SLA_RULE_ID,
      severity: 'info',
      module: 'config',
      file: 'src/a.js',
      line: 3,
      fingerprint: `${SLA_RULE_ID}\0fp-1`,
      message: 'POLICY-SLA-001 294 days past 7 (first-seen)',
    });
  });

  it('emits nothing inside the window, without history, or for a deps clock that is still fresh', () => {
    process.env[FLAG] = '1';
    const rows = [finding()];
    const fresh: HistoryAge[] = [{ fingerprint: 'fp-1', firstSeen: '2026-10-20' }];
    expect(applySla(rows, policy, fresh, scanTime)).toEqual(rows);
    expect(applySla(rows, policy, null, scanTime)).toEqual(rows);
    expect(applySla(rows, policy, [{ fingerprint: 'other', firstSeen: '2020-01-01' }], scanTime)).toEqual(rows);
    const dep = finding({ module: 'deps', fingerprint: 'fp-dep' });
    const depHistory: HistoryAge[] = [{ fingerprint: 'fp-dep', firstSeen: '2026-10-21', osvModified: '2026-10-01' }];
    const late = applySla([dep], policy, depHistory, scanTime);
    expect(late[1]?.message).toBe('POLICY-SLA-001 21 days past 7 (osv-modified)');
    const sastWithOsv = finding();
    const ignored: HistoryAge[] = [{ fingerprint: 'fp-1', firstSeen: '2026-10-20', osvModified: '2020-01-01' }];
    expect(applySla([sastWithOsv], policy, ignored, scanTime)).toEqual([sastWithOsv]);
    expect(() => loadSlaPolicy({ high: 1.5 })).toThrow(FsError);
    expect(() => loadSlaPolicy(['high'])).toThrow('FS-E policy must be an object');
  });
});
