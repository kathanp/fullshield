/**
 * Phase 349. Minimal transitive upgrade proposal.
 * Off unless FULLSHIELD_EXPERIMENTAL_MINUPGRADE=1.
 * Searches cached versions only. An empty cache proposes nothing.
 */

import { compareSemver, rangeSatisfies } from '../modules/deps/semver.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_MINUPGRADE';
export const UNPUBLISHED_FLAG = 'FULLSHIELD_EXPERIMENTAL_NPM_REG_UNPUBLISHED';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface CachedVersion {
  version: string;
  unpublished?: boolean;
}

export interface OsvSpan {
  introduced?: string;
  fixed?: string;
}

export interface UpgradeInput {
  packageName: string;
  parent: string;
  parentRange: string;
  locked: string;
  versions: readonly CachedVersion[];
  ranges: readonly OsvSpan[];
}

export interface UpgradeProposal {
  packageName: string;
  kind: 'bump' | 'nested-override';
  version: string;
  witness?: string;
}

function vulnerable(version: string, ranges: readonly OsvSpan[]): boolean {
  if (ranges.length === 0) {
    return false;
  }
  return ranges.some((range) => {
    const introduced = range.introduced ?? '0.0.0';
    const after = compareSemver(version, introduced) >= 0;
    const beforeFixed = range.fixed === undefined || compareSemver(version, range.fixed) < 0;
    return after && beforeFixed;
  });
}

export function proposeUpgrade(input: UpgradeInput): UpgradeProposal | undefined {
  if (!enabled() || input.versions.length === 0) {
    return undefined;
  }
  const hideUnpublished = process.env[UNPUBLISHED_FLAG] === '1';
  const usable = input.versions.filter((item) => !(hideUnpublished && item.unpublished === true));
  const fixed = usable
    .filter((item) => !vulnerable(item.version, input.ranges))
    .map((item) => item.version)
    .sort((a, b) => compareSemver(a, b));
  const inside = fixed.find((version) => rangeSatisfies(input.parentRange, version) === true);
  if (inside !== undefined) {
    const unpublished = input.versions.find((item) => item.version === inside)?.unpublished === true;
    return {
      packageName: input.packageName,
      kind: 'bump',
      version: inside,
      witness: !hideUnpublished && unpublished ? 'unpublished state was not computed' : undefined,
    };
  }
  const override = fixed[0];
  if (override === undefined) {
    return undefined;
  }
  return { packageName: input.packageName, kind: 'nested-override', version: override, witness: `${input.parent}>${input.packageName}` };
}
