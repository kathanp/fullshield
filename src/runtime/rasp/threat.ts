const scores = new Map<string, number>();

export type ThreatKind = 'block' | 'honey' | 'anomaly';
export type ThreatAction = 'log' | 'challenge' | 'block';

const WEIGHT: Record<ThreatKind, number> = {
  block: 2,
  honey: 5,
  anomaly: 1,
};

export function addThreat(ip: string, kind: ThreatKind): number {
  const next = (scores.get(ip) ?? 0) + WEIGHT[kind];
  scores.set(ip, next);
  return next;
}

export function threatScore(ip: string): number {
  return scores.get(ip) ?? 0;
}

export function clearThreats(): void {
  scores.clear();
}

export function decideResponse(score: number): ThreatAction {
  if (score >= 10) return 'block';
  if (score >= 5) return 'challenge';
  return 'log';
}
