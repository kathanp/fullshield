const scores = new Map<string, number>();
const blockUntil = new Map<string, number>();

export type ThreatKind = 'block' | 'honey' | 'anomaly';
export type ThreatAction = 'log' | 'challenge' | 'block';

const WEIGHT: Record<ThreatKind, number> = {
  block: 2,
  honey: 5,
  anomaly: 1,
};

const DEFAULT_MAX_BLOCK_MS = 15 * 60 * 1000;

let autoBlock = false;
let maxBlockMs = DEFAULT_MAX_BLOCK_MS;

export function configureThreat(opts: { autoBlock?: boolean; maxBlockMs?: number } = {}): void {
  autoBlock = opts.autoBlock === true;
  if (typeof opts.maxBlockMs === 'number' && opts.maxBlockMs > 0) maxBlockMs = opts.maxBlockMs;
}

export function addThreat(ip: string, kind: ThreatKind, now = Date.now()): number {
  const next = (scores.get(ip) ?? 0) + WEIGHT[kind];
  scores.set(ip, next);
  if (autoBlock && next >= 10) {
    blockUntil.set(ip, now + maxBlockMs);
  }
  return next;
}

export function threatScore(ip: string): number {
  return scores.get(ip) ?? 0;
}

export function clearThreats(): void {
  scores.clear();
  blockUntil.clear();
  autoBlock = false;
  maxBlockMs = DEFAULT_MAX_BLOCK_MS;
}

export function decideResponse(score: number): ThreatAction {
  if (score >= 10) return 'block';
  if (score >= 5) return 'challenge';
  return 'log';
}

/**
 * Auto-block is off unless `configureThreat({ autoBlock: true })`.
 * Shared-IP (NAT / carrier-grade NAT) risk: a block applies to the source IP,
 * which may be many users. Keep duration short (`maxBlockMs`).
 */
export function isIpBlocked(ip: string, now = Date.now()): boolean {
  if (!autoBlock) return false;
  const until = blockUntil.get(ip);
  if (until === undefined) return false;
  if (now >= until) {
    blockUntil.delete(ip);
    return false;
  }
  return true;
}

export function threatMaxBlockMs(): number {
  return maxBlockMs;
}

export function threatAutoBlockEnabled(): boolean {
  return autoBlock;
}
