/**
 * Phase 84. Deterministic priority. The point table is docs/priority.md.
 * No ML and no network. Same input always returns the same score.
 */

import type { Confidence, Finding, Severity } from '../core/finding.js';

export const PRIORITY_FLAG = 'FULLSHIELD_EXPERIMENTAL_PRIORITY';

const ALWAYS_100 = new Set(['DEPS-MALICIOUS-001', 'SUPPLY-SECHOLDER-001', 'SUPPLY-STEALER-001']);

const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 80,
  high: 60,
  medium: 40,
  low: 20,
  info: 0,
};

const CONFIDENCE_POINTS: Record<Confidence, number> = {
  high: 10,
  medium: 0,
  low: -10,
};

export interface PriorityInput {
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  reachability?: Finding['reachability'];
  devOnly?: boolean;
  unauthenticatedRoute?: boolean;
  sinkClass?: string;
  agreeingSources?: number;
  kev?: boolean;
}

export interface PriorityScore {
  priority: number;
  priorityFactors: string[];
}

function clamp(value: number): number {
  if (value < 0) return 0;
  if (value > 100) return 100;
  return value;
}

export function priorityScore(input: PriorityInput): PriorityScore {
  if (ALWAYS_100.has(input.ruleId)) {
    return { priority: 100, priorityFactors: [`rule:${input.ruleId}=100`] };
  }
  const factors: string[] = [];
  let total = SEVERITY_POINTS[input.severity];
  factors.push(`severity:${input.severity}+${SEVERITY_POINTS[input.severity]}`);
  const confidence = CONFIDENCE_POINTS[input.confidence];
  total += confidence;
  factors.push(`confidence:${input.confidence}${confidence >= 0 ? '+' : ''}${confidence}`);
  const reach = reachPoints(input.reachability);
  if (reach !== undefined) {
    total += reach.points;
    factors.push(reach.factor);
  }
  if (input.devOnly === true) {
    total -= 15;
    factors.push('dev-only-15');
  }
  if (input.unauthenticatedRoute === true) {
    total += 10;
    factors.push('unauthenticated-route+10');
  }
  if (input.sinkClass !== undefined) {
    const sink = sinkPoints(input.sinkClass);
    total += sink;
    factors.push(`sink:${input.sinkClass}+${sink}`);
  }
  const extra = Math.max(0, (input.agreeingSources ?? 1) - 1) * 5;
  if (extra > 0) {
    total += extra;
    factors.push(`agreeing-sources+${extra}`);
  }
  if (input.kev === true) {
    total += 10;
    factors.push('kev+10');
  }
  return { priority: clamp(total), priorityFactors: factors };
}

function reachPoints(reach: Finding['reachability']): { points: number; factor: string } | undefined {
  if (reach === 'reachable' || reach === 'symbol-reachable') return { points: 10, factor: `reachability:${reach}+10` };
  if (reach === 'reachable-via-dependency') return { points: 5, factor: 'reachability:reachable-via-dependency+5' };
  if (reach === 'imported-not-called') return { points: -5, factor: 'reachability:imported-not-called-5' };
  if (reach === 'not-imported') return { points: -15, factor: 'reachability:not-imported-15' };
  if (reach === 'reachability-unknown') return { points: 0, factor: 'reachability:reachability-unknown+0' };
  if (reach === 'symbol-not-called') return { points: -5, factor: 'reachability:symbol-not-called-5' };
  return undefined;
}

function sinkPoints(sink: string): number {
  if (sink === 'sqli' || sink === 'cmdi' || sink === 'ssrf') return 5;
  if (sink === 'xss' || sink === 'path' || sink === 'nosqli') return 3;
  return 0;
}

export function priorityEnabled(): boolean {
  return process.env[PRIORITY_FLAG] === '1';
}

export function withPriority(finding: Finding, extra: Partial<PriorityInput> = {}): Finding {
  const score = priorityScore({
    ruleId: finding.ruleId,
    severity: finding.severity,
    confidence: finding.confidence,
    reachability: finding.reachability,
    devOnly: finding.message.includes('dev-only') || extra.devOnly === true,
    unauthenticatedRoute: extra.unauthenticatedRoute,
    sinkClass: extra.sinkClass ?? sinkClassOf(finding.ruleId),
    agreeingSources: finding.sources?.length,
    kev: extra.kev,
  });
  return { ...finding, priority: score.priority, priorityFactors: score.priorityFactors };
}

function sinkClassOf(ruleId: string): string | undefined {
  if (ruleId === 'SAST-SQLI-001') return 'sqli';
  if (ruleId === 'SAST-CMDI-001') return 'cmdi';
  if (ruleId === 'SAST-SSRF-001') return 'ssrf';
  if (ruleId === 'SAST-XSS-001') return 'xss';
  if (ruleId === 'SAST-PATH-001') return 'path';
  if (ruleId === 'SAST-NOSQLI-001') return 'nosqli';
  return undefined;
}

export function sortByPriority(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const priority = (b.priority ?? -1) - (a.priority ?? -1);
    if (priority !== 0) return priority;
    const severity = severityOrder(b.severity) - severityOrder(a.severity);
    if (severity !== 0) return severity;
    const file = (a.file ?? '').localeCompare(b.file ?? '');
    if (file !== 0) return file;
    return (a.line ?? 0) - (b.line ?? 0);
  });
}

function severityOrder(severity: Severity): number {
  return SEVERITY_POINTS[severity];
}
