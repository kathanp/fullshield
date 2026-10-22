/**
 * Phase 445. Fix-by dates in policy.
 * Off unless FULLSHIELD_EXPERIMENTAL_SLA=1.
 * Flag off: POLICY-SLA-001 is not emitted.
 * A missing history store emits nothing from this id. Severity of the original finding is unchanged.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SLA';
export const SLA_RULE_ID = 'POLICY-SLA-001';

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

export interface SlaPolicy {
  [severity: string]: number;
}

export interface SlaFinding {
  ruleId: string;
  file: string;
  line: number;
  severity: string;
  module: string;
  fingerprint: string;
  message: string;
}

export interface HistoryAge {
  fingerprint: string;
  firstSeen: string;
  osvModified?: string;
}

const DAY_MS = 86_400_000;

export function loadSlaPolicy(raw: unknown): SlaPolicy {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new FsError('FS-E policy must be an object');
  }
  const policy: SlaPolicy = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw new FsError(`FS-E policy value ${String(value)} is not an integer day count`);
    }
    policy[key] = value;
  }
  return policy;
}

function ageDays(from: string, scanTime: string): number {
  const start = Date.parse(from);
  const end = Date.parse(scanTime);
  if (Number.isNaN(start) || Number.isNaN(end)) {
    return 0;
  }
  return Math.floor((end - start) / DAY_MS);
}

export function applySla(
  findings: readonly SlaFinding[],
  policy: SlaPolicy,
  history: readonly HistoryAge[] | null,
  scanTime: string,
): SlaFinding[] {
  if (!enabled() || history === null) {
    return [...findings];
  }
  const extra: SlaFinding[] = [];
  for (const finding of findings) {
    const row = history.find((item) => item.fingerprint === finding.fingerprint);
    if (row === undefined) {
      continue;
    }
    const limit = policy[finding.severity];
    if (limit === undefined) {
      continue;
    }
    const useOsv = finding.module === 'deps' && row.osvModified !== undefined;
    const clock = useOsv ? 'osv-modified' : 'first-seen';
    const from = useOsv ? row.osvModified ?? row.firstSeen : row.firstSeen;
    const days = ageDays(from, scanTime);
    if (days <= limit) {
      continue;
    }
    extra.push({
      ruleId: SLA_RULE_ID,
      file: finding.file,
      line: finding.line,
      severity: 'info',
      module: 'config',
      fingerprint: `${SLA_RULE_ID}\0${finding.fingerprint}`,
      message: `POLICY-SLA-001 ${days} days past ${limit} (${clock})`,
    });
  }
  return [...findings, ...extra];
}
