/**
 * Phase 377. Duplicate versions with different advisory sets.
 * Off unless FULLSHIELD_EXPERIMENTAL_DUPADV=1.
 * Does not drop DEPS-VULN-001. Does not fetch.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DUPADV';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface LockedCopy {
  name: string;
  version: string;
  lockPath: string;
  /** Null when the OSV cache object is missing. */
  advisoryIds: readonly string[] | null;
}

export interface VulnRow {
  ruleId: 'DEPS-VULN-001';
  name: string;
  version: string;
  advisoryId: string;
}

export interface DupAdvisoryFinding {
  ruleId: 'DEPS-DUP-ADVISORY-001';
  severity: 'medium';
  name: string;
  versions: string[];
  lockPaths: string[];
  onlyOne: string[];
  message: string;
}

export interface SoundnessEvent {
  code: '271';
  message: string;
}

export interface DupAdvisoryResult {
  findings: DupAdvisoryFinding[];
  events: SoundnessEvent[];
  vulns: VulnRow[];
}

function setsDiffer(left: readonly string[], right: readonly string[]): string[] {
  const a = new Set(left);
  const b = new Set(right);
  const only: string[] = [];
  for (const id of a) {
    if (!b.has(id)) {
      only.push(id);
    }
  }
  for (const id of b) {
    if (!a.has(id)) {
      only.push(id);
    }
  }
  only.sort();
  return only;
}

export function duplicateAdvisories(copies: readonly LockedCopy[], vulns: readonly VulnRow[]): DupAdvisoryResult {
  const kept = vulns.map((row) => ({ ...row }));
  if (!enabled()) {
    return { findings: [], events: [], vulns: kept };
  }
  const groups = new Map<string, LockedCopy[]>();
  for (const copy of copies) {
    const list = groups.get(copy.name) ?? [];
    list.push(copy);
    groups.set(copy.name, list);
  }
  const findings: DupAdvisoryFinding[] = [];
  const events: SoundnessEvent[] = [];
  for (const [name, group] of groups) {
    if (group.length < 2) {
      continue;
    }
    if (group.some((copy) => copy.advisoryIds === null)) {
      events.push({ code: '271', message: `OSV cache missing for ${name}` });
      continue;
    }
    const first = group[0];
    const second = group[1];
    if (first === undefined || second === undefined || first.advisoryIds === null || second.advisoryIds === null) {
      continue;
    }
    const onlyOne = setsDiffer(first.advisoryIds, second.advisoryIds);
    if (onlyOne.length === 0) {
      continue;
    }
    findings.push({
      ruleId: 'DEPS-DUP-ADVISORY-001',
      severity: 'medium',
      name,
      versions: group.map((copy) => copy.version),
      lockPaths: group.map((copy) => copy.lockPath),
      onlyOne,
      message: `${name} locks ${group.map((copy) => copy.version).join(' and ')} at ${group.map((copy) => copy.lockPath).join(' and ')} with advisory ids on only one version: ${onlyOne.join(', ')}.`,
    });
  }
  return { findings, events, vulns: kept };
}
