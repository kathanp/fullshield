/**
 * Phase 358. Packument age buckets.
 * Off unless FULLSHIELD_EXPERIMENTAL_POPPROXY=1.
 * Buckets come from the cached time field. This is not a malware finding.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_POPPROXY';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type AgeBucket = 'younger-than-7d' | 'younger-than-30d';

export interface AgeFinding {
  ruleId: 'DEPS-AGE-001';
  severity: 'info';
  packageName: string;
  bucket: AgeBucket;
  versionCount: number;
  message: string;
}

const DAY = 24 * 60 * 60 * 1000;

export function ageBucket(packageName: string, time: Readonly<Record<string, string>> | undefined, direct: boolean, now = new Date()): AgeFinding[] {
  if (!enabled() || !direct || time === undefined) {
    return [];
  }
  const stamps: number[] = [];
  for (const [key, value] of Object.entries(time)) {
    if (key === 'modified') {
      continue;
    }
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) {
      stamps.push(parsed);
    }
  }
  if (stamps.length === 0) {
    return [];
  }
  const earliest = Math.min(...stamps);
  const age = now.getTime() - earliest;
  const bucket: AgeBucket | undefined = age < 7 * DAY ? 'younger-than-7d' : age < 30 * DAY ? 'younger-than-30d' : undefined;
  if (bucket === undefined) {
    return [];
  }
  return [
    {
      ruleId: 'DEPS-AGE-001',
      severity: 'info',
      packageName,
      bucket,
      versionCount: Object.keys(time).filter((key) => key !== 'created' && key !== 'modified').length,
      message: `${packageName} is ${bucket}. This is not a malware finding.`,
    },
  ];
}
