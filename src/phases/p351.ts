/**
 * Phase 351. Lockfile reproducibility check.
 * Off unless FULLSHIELD_EXPERIMENTAL_REPROLOCK=1.
 * Uses the cached packument only. A dist-tag is skipped. npm is not spawned.
 */

import { compareSemver, rangeSatisfies } from '../modules/deps/semver.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_REPROLOCK';
export const RULE = 'DEPS-REPRO-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface ReproDep {
  name: string;
  range: string;
  locked?: string;
  versions?: readonly string[];
  direct: boolean;
}

export interface ReproFinding {
  ruleId: typeof RULE;
  severity: 'medium';
  file: string;
  message: string;
  witness: string;
}

export interface ReproResult {
  findings: ReproFinding[];
  events: { code: 271; file: string; detail: string }[];
}

function highest(range: string, versions: readonly string[]): string | undefined {
  const matches = versions.filter((version) => rangeSatisfies(range, version) === true);
  matches.sort((a, b) => compareSemver(b, a));
  return matches[0];
}

export function reproFindings(deps: readonly ReproDep[]): ReproResult {
  if (!enabled()) {
    return { findings: [], events: [] };
  }
  const findings: ReproFinding[] = [];
  const events: ReproResult['events'] = [];
  for (const dep of deps) {
    if (!dep.direct) {
      continue;
    }
    if (rangeSatisfies(dep.range, dep.locked ?? '0.0.0') === undefined && !dep.range.startsWith('^') && !dep.range.startsWith('~') && !/^\d/.test(dep.range)) {
      events.push({ code: 271, file: dep.name, detail: 'dist-tag is not a version' });
      continue;
    }
    if (dep.versions === undefined) {
      events.push({ code: 271, file: dep.name, detail: 'missing packument' });
      continue;
    }
    const resolved = highest(dep.range, dep.versions);
    if (resolved === undefined || dep.locked === undefined) {
      events.push({ code: 271, file: dep.name, detail: 'missing packument' });
      continue;
    }
    if (dep.locked !== resolved) {
      findings.push({
        ruleId: RULE,
        severity: 'medium',
        file: dep.name,
        message: `${dep.name} lock ${dep.locked} does not match cached resolution ${resolved}.`,
        witness: `${dep.locked} ${resolved}`,
      });
    }
  }
  return { findings, events };
}
