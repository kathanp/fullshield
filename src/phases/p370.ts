/**
 * Phase 370. Fix list ordered by reachability.
 * Off unless FULLSHIELD_EXPERIMENTAL_FIXORDER=1.
 * The sort is the feature. No finding is added or removed.
 * Documented keys: `reachability` (default) and `severity`. There is no third key.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FIXORDER';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type FixReachability =
  | 'runtime-observed'
  | 'function-reachable-via-dependency'
  | 'reachable'
  | 'reachability-unknown'
  | 'not-imported';

export type FixSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface FixProposal {
  packageName: string;
  reachability: FixReachability;
  severity: FixSeverity;
  /** Set when phase 268 observed the package at runtime. */
  runtimeObserved?: boolean;
}

export interface OrderedFixes {
  /** First line of command output. Empty when the flag is off. */
  header: string;
  proposals: FixProposal[];
}

const REACH_RANK: Record<FixReachability, number> = {
  'runtime-observed': 0,
  'function-reachable-via-dependency': 1,
  reachable: 2,
  'reachability-unknown': 3,
  'not-imported': 4,
};

const SEVERITY_RANK: Record<FixSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function reachKey(proposal: FixProposal): FixReachability {
  if (proposal.runtimeObserved === true) {
    return 'runtime-observed';
  }
  return proposal.reachability;
}

export function orderFixes(proposals: readonly FixProposal[], order: 'reachability' | 'severity' = 'reachability'): OrderedFixes {
  if (!enabled()) {
    return { header: '', proposals: [...proposals] };
  }
  const items = [...proposals];
  items.sort((left, right) => {
    const primary =
      order === 'severity'
        ? SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity]
        : REACH_RANK[reachKey(left)] - REACH_RANK[reachKey(right)];
    if (primary !== 0) {
      return primary;
    }
    return left.packageName < right.packageName ? -1 : left.packageName > right.packageName ? 1 : 0;
  });
  return { header: `order: ${order}`, proposals: items };
}
