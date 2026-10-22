/**
 * Phase 427. Local trend report.
 * Off unless FULLSHIELD_EXPERIMENTAL_TREND=1.
 * Flag off: the command fails with FS-E.
 * Counts are local and unreviewed. There is no score.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_TREND';

export class FsError extends Error {
  readonly code = 'FS-E' as const;
  constructor(message: string) {
    super(message);
    this.name = 'FsError';
  }
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface TrendRow {
  scanId: string;
  ruleId: string;
  count: number;
}

export interface TrendOptions {
  format: 'text' | 'json';
  /** The command scans only when the caller passes this. */
  scan?: boolean;
}

export interface TrendResult {
  exitCode: number;
  code?: 'FS-E';
  text: string;
  json: Record<string, unknown> | null;
  startedScan: boolean;
}

const HEADER = 'local unreviewed counts';

export function renderTrend(rows: readonly TrendRow[], options: TrendOptions): TrendResult {
  if (!enabled()) {
    return { exitCode: 1, code: 'FS-E', text: 'FS-E trend is experimental', json: null, startedScan: false };
  }
  const startedScan = options.scan === true;
  const body = rows.map((row) => `${row.scanId} ${row.ruleId} ${row.count}`).join('\n');
  const text = rows.length === 0 ? `${HEADER}\n0` : `${HEADER}\n${body}`;
  const json = { header: HEADER, rows: rows.map((row) => ({ ...row })), count: rows.length };
  if (options.format === 'json') {
    return { exitCode: 0, text: JSON.stringify(json), json, startedScan };
  }
  return { exitCode: 0, text, json, startedScan };
}
