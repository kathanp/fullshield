import type { Confidence, Severity } from '../../core/finding.js';

export interface SecretsRuleMeta {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe?: string;
}

export interface SecretsReport {
  /** 1-based line number. */
  line: number;
  /** The raw matched secret; it is masked before it ever reaches a Finding. */
  secret?: string;
  /** Optional custom message (plain English). */
  message?: string;
}

export interface SecretsRuleContext {
  /** Posix-relative path of the file being scanned. */
  path: string;
  /** Lines with adjacent string-literal concatenation folded. */
  lines: string[];
  /** Original lines. */
  rawLines: string[];
  report(report: SecretsReport): void;
}

export interface SecretsRule {
  meta: SecretsRuleMeta;
  check(ctx: SecretsRuleContext): void;
}
