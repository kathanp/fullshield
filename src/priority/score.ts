import { severityRank, type Confidence, type Finding, type ModuleName, type Severity } from '../core/finding.js';

/** Phase 84. Off unless FULLSHIELD_EXPERIMENTAL_PRIORITY=1 or --experimental-priority. */
export const PRIORITY_FLAG = 'FULLSHIELD_EXPERIMENTAL_PRIORITY';

export function priorityEnabled(): boolean {
  return process.env[PRIORITY_FLAG] === '1';
}

export type RouteExposure = 'unauthenticated' | 'authenticated' | 'unknown';

export interface PriorityFactor {
  name: 'always' | 'severity' | 'confidence' | 'reachability' | 'route' | 'devOnly' | 'sink' | 'sources';
  points: number;
  detail: string;
}

export interface PriorityInput {
  ruleId: string;
  module?: ModuleName;
  severity: Severity;
  confidence: Confidence;
  reachability?: Finding['reachability'];
  routeExposure?: RouteExposure;
  devOnly?: boolean;
  /** Explicit class wins over the rule-id map. Omit it to derive. */
  sinkClass?: string;
  /** Phase 83. Omitted or 1 means a single source. */
  agreeingSources?: number;
}

export interface PriorityScore {
  priority: number;
  factors: PriorityFactor[];
}

const ALWAYS_100 = new Set(['DEPS-MALICIOUS-001', 'SUPPLY-SECHOLDER-001', 'SUPPLY-STEALER-001']);

const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 70,
  high: 55,
  medium: 40,
  low: 20,
  info: 5,
};

const CONFIDENCE_POINTS: Record<Confidence, number> = {
  high: 10,
  medium: 0,
  low: -10,
};

const SINK_POINTS: Record<string, number> = {
  rce: 10,
  injection: 8,
  exposure: 5,
  proto: 4,
  credential: 2,
  none: 0,
};

const RULE_SINK: Record<string, string> = {
  'SAST-CMDI-001': 'rce',
  'SAST-EVAL-001': 'rce',
  'SAST-SQLI-001': 'injection',
  'SAST-NOSQLI-001': 'injection',
  'SAST-SSRF-001': 'exposure',
  'SAST-PATH-001': 'exposure',
  'SAST-XSS-001': 'exposure',
  'SAST-REDIRECT-001': 'exposure',
  'SAST-PROTO-001': 'proto',
  'SAST-JWT-001': 'credential',
  'SAST-CRYPTO-001': 'credential',
  'SAST-AUTH-001': 'credential',
};

function clampPriority(value: number): number {
  if (value < 0) {return 0;}
  if (value > 100) {return 100;}
  return value;
}

function reachPoints(value: Finding['reachability'] | undefined): { points: number; detail: string } {
  switch (value) {
    case 'reachable':
    case 'symbol-reachable':
      return { points: 10, detail: value };
    case 'reachable-via-dependency':
      return { points: 5, detail: value };
    case 'imported-not-called':
    case 'symbol-not-called':
      return { points: -5, detail: value };
    case 'not-imported':
      return { points: -15, detail: value };
    case 'reachability-unknown':
    case 'vendored':
      return { points: 0, detail: value };
    case undefined:
      return { points: 0, detail: 'absent' };
    default: {
      const never: never = value;
      return never;
    }
  }
}

function routePoints(value: RouteExposure | undefined): { points: number; detail: string } {
  if (value === 'unauthenticated') {return { points: 10, detail: value };}
  if (value === 'authenticated') {return { points: 0, detail: value };}
  return { points: 0, detail: 'unknown' };
}

function devPoints(value: boolean | undefined): { points: number; detail: string } {
  if (value === true) {return { points: -20, detail: 'yes' };}
  return { points: 0, detail: 'no' };
}

function sinkPoints(input: PriorityInput): { points: number; detail: string } {
  if (input.sinkClass !== undefined) {
    return { points: SINK_POINTS[input.sinkClass] ?? 0, detail: input.sinkClass };
  }
  const mapped = RULE_SINK[input.ruleId];
  if (mapped !== undefined) {
    return { points: SINK_POINTS[mapped] ?? 0, detail: mapped };
  }
  if (input.module === 'secrets') {return { points: 2, detail: 'credential' };}
  return { points: 0, detail: 'none' };
}

function sourcePoints(count: number | undefined): { points: number; detail: string } {
  const n = count === undefined || !Number.isFinite(count) ? 1 : Math.max(0, Math.trunc(count));
  let points = 0;
  if (n >= 4) {points = 15;}
  else if (n === 3) {points = 10;}
  else if (n === 2) {points = 5;}
  return { points, detail: String(n) };
}

function routeFromFinding(finding: Finding): RouteExposure {
  if (finding.ruleId === 'SAST-AUTH-001' || /no auth middleware/i.test(finding.message)) {
    return 'unauthenticated';
  }
  return 'unknown';
}

/** Documented table in docs/priority.md. Same input always returns the same score. */
export function scorePriority(input: PriorityInput): PriorityScore {
  if (ALWAYS_100.has(input.ruleId)) {
    return {
      priority: 100,
      factors: [{ name: 'always', points: 100, detail: input.ruleId }],
    };
  }
  const factors: PriorityFactor[] = [
    { name: 'severity', points: SEVERITY_POINTS[input.severity], detail: input.severity },
    { name: 'confidence', points: CONFIDENCE_POINTS[input.confidence], detail: input.confidence },
    { name: 'reachability', ...reachPoints(input.reachability) },
    { name: 'route', ...routePoints(input.routeExposure) },
    { name: 'devOnly', ...devPoints(input.devOnly) },
    { name: 'sink', ...sinkPoints(input) },
    { name: 'sources', ...sourcePoints(input.agreeingSources) },
  ];
  const sum = factors.reduce((total, item) => total + item.points, 0);
  return { priority: clampPriority(sum), factors };
}

/** Score a finding. Does not change severity. Phase 56 data is not read. */
export function scoreFinding(finding: Finding): PriorityScore {
  return scorePriority({
    ruleId: finding.ruleId,
    module: finding.module,
    severity: finding.severity,
    confidence: finding.confidence,
    reachability: finding.reachability,
    routeExposure: routeFromFinding(finding),
    devOnly: finding.message.includes('(dev-only)'),
    agreeingSources: finding.sources?.length,
  });
}

/** Attach priority fields only when the flag is on. Order and severity stay as given. */
export function applyPriority(findings: readonly Finding[]): Finding[] {
  if (!priorityEnabled()) {return [...findings];}
  return findings.map((finding) => {
    const scored = scoreFinding(finding);
    return {
      ...finding,
      severity: finding.severity,
      priority: scored.priority,
      priorityFactors: scored.factors,
    };
  });
}

/** Console order when the flag is on: priority, then severity, then file. */
export function compareByPriority(a: Finding, b: Finding): number {
  return (
    (b.priority ?? 0) - (a.priority ?? 0) ||
    severityRank(b.severity) - severityRank(a.severity) ||
    (a.file ?? '').localeCompare(b.file ?? '') ||
    (a.line ?? 0) - (b.line ?? 0) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}
