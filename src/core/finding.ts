import { createHash } from 'node:crypto';

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const MODULE_NAMES = ['deps', 'secrets', 'sast', 'config'] as const;
export type ModuleName = (typeof MODULE_NAMES)[number];

export type Confidence = 'low' | 'medium' | 'high';

export interface FixProposal {
  kind: 'dependency-bump' | 'code-patch' | 'config-add' | 'dependency-override';
  /** Only safe fixes apply without --unsafe. */
  safe: boolean;
  /** Unified diff. */
  diff: string;
}

export interface Finding {
  /** Stable hash of ruleId + file + normalized snippet. */
  id: string;
  /** e.g. "SAST-SQLI-001" */
  ruleId: string;
  module: ModuleName;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** e.g. "CWE-89" */
  cwe?: string;
  file?: string;
  line?: number;
  column?: number;
  /** Secrets MUST be masked: first 4 chars + **** */
  snippet?: string;
  /** What's wrong, in plain English. */
  message: string;
  /** How to fix. */
  remediation: string;
  fix?: FixProposal;
  /** OSV id, CVE, docs. */
  references?: string[];
  /** Cross-file taint steps (Phase 13). */
  trace?: Array<{ file: string; line?: number; note: string }>;
  /** Dependency reachability (Phase 13 / harden-3). */
  reachability?:
    | 'reachable'
    | 'imported-not-called'
    | 'reachable-via-dependency'
    | 'not-imported'
    | 'reachability-unknown'
    | 'symbol-reachable'
    | 'symbol-not-called';
  /** Lockfile path from an imported direct dependency, e.g. express > body-parser > qs. */
  dependencyPath?: string[];
  /** Every retained dependency path for this package+advisory (shortest first). */
  dependencyPaths?: string[][];
  /** Deterministic (default) vs AI-added. AI findings never fail CI. */
  source?: 'deterministic' | 'ai';
  aiVerdict?: 'true-positive' | 'likely-false-positive' | 'needs-review';
  aiReasoning?: string;
  exploitScenario?: string;
  explanation?: string;
  /** Git commit that first introduced this secret (`scan --history`). */
  introducedIn?: string;
  /** Whether the secret still exists at HEAD (`scan --history`). */
  stillAtHead?: boolean;
  /** Read-only identity check (`scan --verify-secrets`). Never includes the secret. */
  verification?: 'live' | 'revoked' | 'unknown';
  /** Phase 83 tool names that agreed on this finding. Absent until ingest sets it. */
  sources?: string[];
  /** 0–100. Present only with FULLSHIELD_EXPERIMENTAL_PRIORITY=1. Severity is never changed. */
  priority?: number;
  /** Why `priority` was chosen. Same flag as `priority`. */
  priorityFactors?: Array<{ name: string; points: number; detail: string }>;
  /**
   * Offline structure check. Present only with FULLSHIELD_EXPERIMENTAL_SECRET_CHECK=1.
   * Never deletes the finding and never changes severity.
   */
  secretCheck?: 'checksum-failed' | 'placeholder';
  /** Set to `test` for test, fixture, example, and sample paths. Flag-only. */
  context?: 'test';
  /** Why the reachability class was chosen. Present only with FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE=1. */
  reachabilityEvidence?: {
    imports: Array<{ file: string; line: number; specifier: string }>;
    calls?: Array<{ file: string; line: number; symbol: string }>;
    dependencyPath?: string[];
    reason: string;
  };
}

export interface FindingSummary {
  total: number;
  bySeverity: Record<Severity, number>;
}

export function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

export function isModuleName(value: string): value is ModuleName {
  return (MODULE_NAMES as readonly string[]).includes(value);
}

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

/** True when `severity` is at or above `threshold`. */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) >= severityRank(threshold);
}

/** CI gate: deterministic findings only. `source: 'ai'` never fails a build. */
export function failsCi(finding: Finding, threshold: Severity): boolean {
  if (finding.source === 'ai') return false;
  return meetsThreshold(finding.severity, threshold);
}

/** Stable finding id: sha256 of ruleId + file + whitespace-normalized snippet. */
export function makeFindingId(
  ruleId: string,
  file: string | undefined,
  snippet: string | undefined,
): string {
  const normalized = (snippet ?? '').replace(/\s+/g, ' ').trim();
  return createHash('sha256')
    .update(`${ruleId}\u0000${file ?? ''}\u0000${normalized}`)
    .digest('hex')
    .slice(0, 16);
}

/** Sort by severity (desc), then file, line, ruleId for stable output. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      (a.file ?? '').localeCompare(b.file ?? '') ||
      (a.line ?? 0) - (b.line ?? 0) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

export function summarize(findings: readonly Finding[]): FindingSummary {
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
  }
  return { total: findings.length, bySeverity };
}
