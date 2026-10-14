import type { Finding } from './finding.js';

/** Findings in `current` whose stable id was not present in the previous scan. */
export function diffNewFindings(current: readonly Finding[], previousIds: ReadonlySet<string>): Finding[] {
  return current.filter((f) => !previousIds.has(f.id));
}
