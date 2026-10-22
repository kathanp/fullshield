/**
 * Phase 450. Performance report.
 * Off unless FULLSHIELD_EXPERIMENTAL_PERFREPT=1.
 * Flag off: --perf errors with FS-E and findings are unchanged. Omitting --perf still returns findings.
 * Timings are not added to the finding document.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PERFREPT';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PerfRow {
  phase: string;
  ms: number;
}

export interface PerfFile {
  unreviewed: true;
  phases: PerfRow[];
  peakRss: number;
}

export interface PerfResult {
  findings: unknown;
  side: PerfFile | null;
  exitCode: number;
  code?: 'FS-E';
}

export function withPerf(findings: unknown, rows: readonly PerfRow[], peakRss: number, perfPath: string | undefined): PerfResult {
  if (perfPath === undefined) {
    return { findings, side: null, exitCode: 0 };
  }
  if (!enabled()) {
    return { findings, side: null, exitCode: 1, code: 'FS-E' };
  }
  return {
    findings,
    side: { unreviewed: true, phases: rows.map((row) => ({ phase: row.phase, ms: row.ms })), peakRss },
    exitCode: 0,
  };
}
