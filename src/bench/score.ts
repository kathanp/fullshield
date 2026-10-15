export const BENCH_CLASSES = [
  'sqli',
  'nosqli',
  'cmdi',
  'path',
  'xss',
  'ssrf',
  'redirect',
  'eval',
  'jwt',
  'crypto',
  'proto',
  'secrets',
  'deps',
  'config',
  'other',
] as const;

export type BenchClass = (typeof BENCH_CLASSES)[number];

/** Classes FullShield claims to detect statically (Phase 26 in-scope set). */
export const IN_SCOPE_CLASSES: readonly BenchClass[] = [
  'sqli',
  'nosqli',
  'cmdi',
  'path',
  'xss',
  'ssrf',
  'redirect',
  'eval',
  'jwt',
  'crypto',
  'proto',
  'secrets',
  'deps',
  'config',
];

export interface GroundTruthEntry {
  class: BenchClass;
  file: string;
  line: number;
  description: string;
  source: string;
  inScope: boolean;
  reason?: string;
}

export interface FindingLike {
  ruleId: string;
  file?: string;
  line?: number;
}

export type TriageVerdict = 'realIssue' | 'falsePositive' | 'unsure';

export interface TriageEntry {
  ruleId: string;
  file: string;
  line: number;
  verdict: TriageVerdict;
  reason: string;
}

const RULE_CLASS: Record<string, BenchClass> = {
  'SAST-SQLI-001': 'sqli',
  'SAST-NOSQLI-001': 'nosqli',
  'SAST-CMDI-001': 'cmdi',
  'SAST-PATH-001': 'path',
  'SAST-XSS-001': 'xss',
  'SAST-SSRF-001': 'ssrf',
  'SAST-REDIRECT-001': 'redirect',
  'SAST-EVAL-001': 'eval',
  'SAST-JWT-001': 'jwt',
  'SAST-CRYPTO-001': 'crypto',
  'SAST-PROTO-001': 'proto',
};

export function classForRule(ruleId: string): BenchClass {
  if (RULE_CLASS[ruleId]) return RULE_CLASS[ruleId];
  if (ruleId.startsWith('SECRET-')) return 'secrets';
  if (ruleId.startsWith('DEPS-')) return 'deps';
  if (ruleId.startsWith('CONFIG-')) return 'config';
  return 'other';
}

function normFile(file: string): string {
  return file.replaceAll('\\', '/').replace(/^\.\//, '');
}

export function findingKey(finding: FindingLike): string {
  return `${finding.ruleId}|${normFile(finding.file ?? '')}|${finding.line ?? 0}`;
}

export function isTruePositive(finding: FindingLike, truth: GroundTruthEntry): boolean {
  if (classForRule(finding.ruleId) !== truth.class) return false;
  if (!finding.file) return false;
  const ff = normFile(finding.file);
  const tf = normFile(truth.file);
  if (ff !== tf && !ff.endsWith(`/${tf}`) && !tf.endsWith(`/${ff}`)) return false;
  const line = finding.line ?? 0;
  return Math.abs(line - truth.line) <= 3;
}

export interface ScoreResult {
  truePositives: GroundTruthEntry[];
  inScopeMisses: GroundTruthEntry[];
  outOfScope: GroundTruthEntry[];
  unmatched: FindingLike[];
}

export function scoreFindings(findings: FindingLike[], truth: GroundTruthEntry[]): ScoreResult {
  const used = new Set<number>();
  const truePositives: GroundTruthEntry[] = [];
  const inScope = truth.filter((e) => e.inScope === true);
  const outOfScope = truth.filter((e) => e.inScope !== true);
  for (const entry of inScope) {
    const hit = findings.findIndex((f, i) => !used.has(i) && isTruePositive(f, entry));
    if (hit >= 0) {
      used.add(hit);
      truePositives.push(entry);
    }
  }
  const inScopeMisses = inScope.filter((e) => !truePositives.includes(e));
  const unmatched = findings.filter((_, i) => !used.has(i));
  return { truePositives, inScopeMisses, outOfScope, unmatched };
}

export function precisionFromTriage(entries: Array<{ verdict: TriageVerdict; reason: string }>): {
  realIssue: number;
  falsePositive: number;
  unsure: number;
  precision: string;
} {
  const realIssue = entries.filter((e) => e.verdict === 'realIssue').length;
  const falsePositive = entries.filter((e) => e.verdict === 'falsePositive').length;
  const unsure = entries.filter((e) => e.verdict === 'unsure').length;
  const den = realIssue + falsePositive;
  const precision = den === 0 ? 'n/a' : `${((100 * realIssue) / den).toFixed(1)}%`;
  return { realIssue, falsePositive, unsure, precision };
}
