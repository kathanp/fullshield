import { afterEach, describe, expect, it } from 'vitest';

import {
  enabled,
  FLAG,
  historyCounts,
  historyKey,
  historyNote,
  openHistory,
  readHistory,
  recordScan,
  schemaObjects,
  type HistoryFinding,
} from '../../../src/phases/p426.js';

afterEach(() => {
  delete process.env[FLAG];
  delete process.env.FULLSHIELD_EXPERIMENTAL_STABLEFP;
});

const finding: HistoryFinding = { ruleId: 'SAST-SQLI-001', file: 'src/db.js', line: 4 };

describe('phase 426 local finding history', () => {
  it('does not create the history table when the flag is off', () => {
    expect(enabled()).toBe(false);
    const db = openHistory(':memory:');
    recordScan(db, [finding], '2026-01-01');
    expect(schemaObjects(db)).not.toContain('history');
    expect(readHistory(db)).toEqual([]);
    expect(historyCounts(db)).toBe('the key includes the line\nopen 0\nabsent 0');
    db.close();
  });

  it('marks a dropped finding absent and keeps a suppressed row', () => {
    process.env[FLAG] = '1';
    const db = openHistory(':memory:');
    const suppressed: HistoryFinding = { ruleId: 'SAST-XSS-001', file: 'src/view.js', line: 2, suppressed: true };
    recordScan(db, [finding, suppressed], '2026-01-01');
    recordScan(db, [suppressed], '2026-01-02');
    const rows = readHistory(db);
    const sql = rows.find((row) => row.ruleId === 'SAST-SQLI-001');
    const xss = rows.find((row) => row.ruleId === 'SAST-XSS-001');
    expect(sql?.state).toBe('absent');
    expect(sql?.firstSeen).toBe('2026-01-01');
    expect(sql?.lastSeen).toBe('2026-01-02');
    expect(sql?.fingerprint).toBe(historyKey(finding));
    expect(xss?.state).toBe('suppressed');
    expect(historyCounts(db)).toBe('the key includes the line\nopen 0\nabsent 1');
    expect(schemaObjects(db)).toContain('history');
    db.close();
  });

  it('keeps a finding that is still present and separates lines', () => {
    process.env[FLAG] = '1';
    const db = openHistory(':memory:');
    recordScan(db, [finding], '2026-01-01');
    recordScan(db, [finding], '2026-01-02');
    const rows = readHistory(db);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.state).toBe('open');
    expect(rows[0]?.firstSeen).toBe('2026-01-01');
    expect(rows[0]?.lastSeen).toBe('2026-01-02');
    recordScan(db, [{ ...finding, line: 9 }], '2026-01-03');
    const moved = readHistory(db);
    expect(moved.find((row) => row.line === 4)?.state).toBe('absent');
    expect(moved.find((row) => row.line === 9)?.state).toBe('open');
    expect(historyKey(finding)).toContain('\0src/db.js\0');
    expect(historyNote()).toBe('the key includes the line');
    process.env.FULLSHIELD_EXPERIMENTAL_STABLEFP = '1';
    expect(historyNote()).toBe('fingerprint ignores the line');
    db.close();
  });
});
