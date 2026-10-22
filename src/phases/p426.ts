/**
 * Phase 426. Local finding history.
 * Off unless FULLSHIELD_EXPERIMENTAL_HISTORY=1.
 * Flag off: the database schema is not created or altered.
 * The store stays on this machine. This module does not open a network connection.
 */
import { createRequire } from 'node:module';
import type { DatabaseSync } from 'node:sqlite';

const require = createRequire(import.meta.url);
const { DatabaseSync: SqliteDatabase } = require('node:sqlite') as {
  DatabaseSync: new (path: string) => DatabaseSync;
};

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_HISTORY';
export const HISTORY_DB_PATH = '.fullshield/history.sqlite';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface HistoryFinding {
  ruleId: string;
  file: string;
  line: number;
  suppressed?: boolean;
}

export interface HistoryRow {
  fingerprint: string;
  firstSeen: string;
  lastSeen: string;
  state: string;
  ruleId: string;
  file: string;
  line: number;
}

export function historyKey(finding: HistoryFinding): string {
  return `${finding.ruleId}\0${finding.file}\0${finding.line}`;
}

/** Until refactor-stable fingerprints are on, the history key includes the line. */
export function historyNote(): string {
  if (process.env.FULLSHIELD_EXPERIMENTAL_STABLEFP === '1') {
    return 'fingerprint ignores the line';
  }
  return 'the key includes the line';
}

function ensure(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS history (
    fingerprint TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    state TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL
  )`);
}

export function openHistory(path: string): DatabaseSync {
  return new SqliteDatabase(path);
}

export function recordScan(db: DatabaseSync, findings: readonly HistoryFinding[], when: string): void {
  if (!enabled()) {
    return;
  }
  ensure(db);
  const seen = new Set<string>();
  const upsert = db.prepare(
    `INSERT INTO history (fingerprint, first_seen, last_seen, state, rule_id, file, line)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(fingerprint) DO UPDATE SET
       last_seen = excluded.last_seen,
       state = excluded.state`,
  );
  for (const finding of findings) {
    const fingerprint = historyKey(finding);
    seen.add(fingerprint);
    const state = finding.suppressed === true ? 'suppressed' : 'open';
    upsert.run(fingerprint, when, when, state, finding.ruleId, finding.file, finding.line);
  }
  const rows = db.prepare('SELECT fingerprint FROM history').all() as Array<{ fingerprint: string }>;
  const mark = db.prepare(`UPDATE history SET state = 'absent', last_seen = ? WHERE fingerprint = ?`);
  for (const row of rows) {
    if (!seen.has(row.fingerprint)) {
      mark.run(when, row.fingerprint);
    }
  }
}

export function readHistory(db: DatabaseSync): HistoryRow[] {
  if (!enabled()) {
    return [];
  }
  const rows = db.prepare(
    'SELECT fingerprint, first_seen, last_seen, state, rule_id, file, line FROM history ORDER BY fingerprint',
  ).all() as Array<{
    fingerprint: string;
    first_seen: string;
    last_seen: string;
    state: string;
    rule_id: string;
    file: string;
    line: number;
  }>;
  return rows.map((row) => ({
    fingerprint: row.fingerprint,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    state: row.state,
    ruleId: row.rule_id,
    file: row.file,
    line: row.line,
  }));
}

export function historyCounts(db: DatabaseSync): string {
  const rows = readHistory(db);
  const open = rows.filter((row) => row.state === 'open').length;
  const absent = rows.filter((row) => row.state === 'absent').length;
  return `${historyNote()}\nopen ${open}\nabsent ${absent}`;
}

export function schemaObjects(db: DatabaseSync): string[] {
  const rows = db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as Array<{ name: string }>;
  return rows.map((row) => row.name);
}
