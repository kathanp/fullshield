import type { Severity } from '../../core/finding.js';

export function parseSemver(version: string): [number, number, number] {
  const core = version.split('-')[0]?.split('+')[0] ?? '0.0.0';
  const parts = core.split('.').map((p) => {
    const n = Number.parseInt(p, 10);
    return Number.isFinite(n) ? n : 0;
  });
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  return pa[0] - pb[0] || pa[1] - pb[1] || pa[2] - pb[2];
}

export function sameMajor(a: string, b: string): boolean {
  return parseSemver(a)[0] === parseSemver(b)[0];
}

interface OsvRange {
  events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
}

interface OsvAffected {
  ranges?: OsvRange[];
}

/** Minimum version that includes every listed `fixed` event (linear semver). */
export function minFixedVersion(affected: readonly OsvAffected[]): string | undefined {
  let best: string | undefined;
  for (const entry of affected) {
    for (const range of entry.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed === undefined) continue;
        if (best === undefined || compareSemver(event.fixed, best) > 0) {
          best = event.fixed;
        }
      }
    }
  }
  return best;
}

export interface OsvSeverityInput {
  database_specific?: { severity?: string };
  severity?: Array<{ type?: string; score?: string }>;
}

function fromCvssScore(score: string): Severity | undefined {
  const n = Number.parseFloat(score.split('/')[0] ?? score);
  if (!Number.isFinite(n)) return undefined;
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  return 'low';
}

/** Map OSV severity metadata onto a Finding severity. Unknown → high. */
export function osvSeverity(vuln: OsvSeverityInput): Severity {
  const raw = vuln.database_specific?.severity?.toUpperCase();
  if (raw === 'CRITICAL') return 'critical';
  if (raw === 'HIGH') return 'high';
  if (raw === 'MODERATE' || raw === 'MEDIUM') return 'medium';
  if (raw === 'LOW') return 'low';
  for (const entry of vuln.severity ?? []) {
    if (entry.score !== undefined) {
      const mapped = fromCvssScore(entry.score);
      if (mapped !== undefined) return mapped;
    }
  }
  return 'high';
}
