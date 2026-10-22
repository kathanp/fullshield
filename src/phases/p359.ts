/**
 * Phase 359. Publish-cadence buckets.
 * Off unless FULLSHIELD_EXPERIMENTAL_CADENCE=1.
 * Two documented shapes. The message does not say malicious.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CADENCE';
export const BURST = 'more-than-10-in-7d';
export const GAP = 'gap-180d-then-recent';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface CadenceFinding {
  ruleId: 'DEPS-CADENCE-001';
  severity: 'info';
  packageName: string;
  shape: typeof BURST | typeof GAP;
  message: string;
}

const DAY = 24 * 60 * 60 * 1000;

export function cadence(packageName: string, time: Readonly<Record<string, string>> | undefined, now = new Date()): CadenceFinding[] {
  if (!enabled() || time === undefined) {
    return [];
  }
  const stamps = Object.entries(time)
    .filter(([key]) => key !== 'created' && key !== 'modified')
    .map(([, value]) => Date.parse(value))
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => a - b);
  if (stamps.length === 0) {
    return [];
  }
  const recent = stamps.filter((stamp) => now.getTime() - stamp <= 7 * DAY);
  if (recent.length > 10) {
    return [{ ruleId: 'DEPS-CADENCE-001', severity: 'info', packageName, shape: BURST, message: `${packageName} matches ${BURST}.` }];
  }
  const newest = stamps[stamps.length - 1];
  const previous = stamps.length > 1 ? stamps[stamps.length - 2] : undefined;
  if (newest !== undefined && now.getTime() - newest <= 7 * DAY && previous !== undefined && newest - previous >= 180 * DAY) {
    return [{ ruleId: 'DEPS-CADENCE-001', severity: 'info', packageName, shape: GAP, message: `${packageName} matches ${GAP}.` }];
  }
  return [];
}
