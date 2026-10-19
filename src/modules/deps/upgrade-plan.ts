import { compareSemver, sameMajor } from './semver.js';

export interface UpgradeAdvisory {
  name: string;
  from: string;
  id: string;
  /** A `fixed` version copied from the OSV cache. Absent means OSV named none. */
  fixed?: string;
}

export interface UpgradeBump {
  name: string;
  from: string;
  to: string;
  safe: boolean;
  findings: number;
}

export interface UpgradePlan {
  bumps: UpgradeBump[];
  unresolved: string[];
  sentence: string;
}

interface Candidate {
  name: string;
  from: string;
  to: string;
  ids: string[];
}

function sentenceFor(bumps: readonly UpgradeBump[], unresolved: readonly string[]): string {
  const parts: string[] = [];
  if (bumps.length === 1) {
    const bump = bumps[0];
    if (bump !== undefined) {
      const noun = bump.findings === 1 ? 'finding' : 'findings';
      parts.push(`1 bump (${bump.name} ${bump.from} → ${bump.to}) resolves ${bump.findings} ${noun}.`);
    }
  } else if (bumps.length > 1) {
    const listed = bumps.map((bump) => `${bump.name} ${bump.from} → ${bump.to}`).join(', ');
    const total = bumps.reduce((sum, bump) => sum + bump.findings, 0);
    const noun = total === 1 ? 'finding' : 'findings';
    parts.push(`${bumps.length} bumps (${listed}) resolve ${total} ${noun}.`);
  }
  if (unresolved.length > 0) {
    parts.push(`No fixed version in the OSV cache for ${unresolved.join(', ')}.`);
  }
  return parts.join(' ');
}

/**
 * Smallest set of direct bumps that clears the most advisories.
 * A bump target is only a `fixed` version from the cache. Ties: fewer bumps, then package name.
 */
export function chooseUpgradePlan(advisories: readonly UpgradeAdvisory[]): UpgradePlan | undefined {
  const byName = new Map<string, UpgradeAdvisory[]>();
  for (const advisory of advisories) {
    const list = byName.get(advisory.name);
    if (list === undefined) byName.set(advisory.name, [advisory]);
    else list.push(advisory);
  }
  const unresolved: string[] = [];
  const candidates: Candidate[] = [];
  for (const [name, list] of byName) {
    const from = list[0]?.from ?? '0.0.0';
    if (list.some((advisory) => advisory.fixed === undefined)) {
      unresolved.push(name);
      continue;
    }
    let to = list[0]?.fixed;
    for (const advisory of list) {
      if (advisory.fixed !== undefined && (to === undefined || compareSemver(advisory.fixed, to) > 0)) {
        to = advisory.fixed;
      }
    }
    if (to === undefined || compareSemver(to, from) <= 0) continue;
    candidates.push({
      name,
      from,
      to,
      ids: list.map((advisory) => advisory.id),
    });
  }
  unresolved.sort();
  const chosen = smallestMaxCover(candidates);
  if (chosen.length === 0 && unresolved.length === 0) return undefined;
  const bumps: UpgradeBump[] = chosen.map((candidate) => ({
    name: candidate.name,
    from: candidate.from,
    to: candidate.to,
    safe: sameMajor(candidate.from, candidate.to),
    findings: candidate.ids.length,
  }));
  return { bumps, unresolved, sentence: sentenceFor(bumps, unresolved) };
}

function smallestMaxCover(candidates: readonly Candidate[]): Candidate[] {
  const limit = Math.min(candidates.length, 12);
  let best: Candidate[] = [];
  let bestCount = -1;
  const walk = (index: number, picked: Candidate[], covered: Set<string>): void => {
    if (index === limit) {
      if (covered.size > bestCount || (covered.size === bestCount && betterTie(picked, best))) {
        best = picked;
        bestCount = covered.size;
      }
      return;
    }
    const next = candidates[index];
    if (next === undefined) return;
    walk(index + 1, picked, covered);
    const grown = new Set(covered);
    for (const id of next.ids) grown.add(id);
    walk(index + 1, [...picked, next], grown);
  };
  walk(0, [], new Set());
  return [...best].sort((a, b) => a.name.localeCompare(b.name));
}

function betterTie(picked: readonly Candidate[], best: readonly Candidate[]): boolean {
  if (picked.length !== best.length) return picked.length < best.length;
  const left = picked.map((item) => item.name).sort().join('\0');
  const right = best.map((item) => item.name).sort().join('\0');
  return left < right;
}
