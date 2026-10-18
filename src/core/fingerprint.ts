import { makeFindingId, type Finding } from './finding.js';

/**
 * Identity of a finding that ignores the line number.
 * Same rule, file, severity, and text stay one finding when the line shifts.
 */
export function lineIndependentFingerprint(
  finding: Pick<Finding, 'ruleId' | 'file' | 'severity' | 'snippet' | 'message'>,
): string {
  const file = (finding.file ?? '').replace(/\\/g, '/');
  const text = (finding.snippet ?? finding.message ?? '').replace(/\s+/g, ' ').trim();
  return makeFindingId(finding.ruleId, file, `${finding.severity}\u0000${text}`);
}
