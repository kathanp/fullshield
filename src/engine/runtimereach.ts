/** Phase 268. Observation can upgrade a finding. Absence never downgrades it. */
export const RUNTIMEREACH_FLAG = 'FULLSHIELD_EXPERIMENTAL_RUNTIMEREACH';

function runtimeReachEnabled(): boolean {
  return process.env[RUNTIMEREACH_FLAG] === '1';
}

export interface Observation {
  module: string;
  exportName: string;
  calls: number;
}

export interface ReachMark {
  reachability: string;
  runtimeObserved: boolean;
}

export function markObserved(
  current: string,
  moduleName: string,
  exportName: string,
  observations: readonly Observation[],
): ReachMark {
  if (!runtimeReachEnabled()) {return { reachability: current, runtimeObserved: false };}
  const hit = observations.some((row) => row.module === moduleName && row.exportName === exportName && row.calls > 0);
  if (!hit) {return { reachability: current, runtimeObserved: false };}
  return { reachability: current, runtimeObserved: true };
}

/** Hook failure keeps the static result. */
export function observeOrFailOpen(current: string, read: () => Observation[]): ReachMark {
  try {
    const rows = read();
    const first = rows[0];
    return markObserved(current, first?.module ?? '', first?.exportName ?? '', rows);
  } catch {
    return { reachability: current, runtimeObserved: false };
  }
}
