export const BENCH_CLASSES = [
  'sqli',
  'nosqli',
  'cmdi',
  'path',
  'xss',
  'ssrf',
  'redirect',
  'secrets',
  'deps',
  'config',
  'auth',
  'other',
] as const;

export type BenchClass = (typeof BENCH_CLASSES)[number];

export interface GroundTruthEntry {
  class: BenchClass;
  file: string;
  line: number;
  description: string;
  source: string;
}

export interface FindingLike {
  ruleId: string;
  file?: string;
  line?: number;
}

const RULE_CLASS: Record<string, BenchClass> = {
  'SAST-SQLI-001': 'sqli',
  'SAST-NOSQLI-001': 'nosqli',
  'SAST-CMDI-001': 'cmdi',
  'SAST-PATH-001': 'path',
  'SAST-XSS-001': 'xss',
  'SAST-SSRF-001': 'ssrf',
  'SAST-REDIRECT-001': 'redirect',
  'SAST-AUTH-001': 'auth',
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
  misses: GroundTruthEntry[];
  falsePositives: FindingLike[];
}

export function scoreFindings(findings: FindingLike[], truth: GroundTruthEntry[]): ScoreResult {
  const used = new Set<number>();
  const truePositives: GroundTruthEntry[] = [];
  for (const entry of truth) {
    const hit = findings.findIndex((f, i) => !used.has(i) && isTruePositive(f, entry));
    if (hit >= 0) {
      used.add(hit);
      truePositives.push(entry);
    }
  }
  const misses = truth.filter((e) => !truePositives.includes(e));
  const falsePositives = findings.filter((_, i) => !used.has(i));
  return { truePositives, misses, falsePositives };
}
