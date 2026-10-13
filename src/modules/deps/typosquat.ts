import type { LockedPackage } from './lockfile.js';
import { POPULAR_PACKAGES } from './popular.js';

export interface TyposquatHit {
  name: string;
  version: string;
  path: string;
  lookalike: string;
  distance: number;
}

const popularSet = new Set(POPULAR_PACKAGES);

function levenshteinAtMost1(a: string, b: string): number | undefined {
  if (a === b) return 0;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return undefined;
  // Equal length: at most one substitution.
  if (la === lb) {
    let diffs = 0;
    for (let i = 0; i < la; i += 1) {
      if (a[i] !== b[i]) {
        diffs += 1;
        if (diffs > 1) return undefined;
      }
    }
    return diffs;
  }
  // Insertion / deletion of a single character.
  const shorter = la < lb ? a : b;
  const longer = la < lb ? b : a;
  let si = 0;
  let skipped = false;
  for (let li = 0; li < longer.length; li += 1) {
    if (shorter[si] === longer[li]) {
      si += 1;
      continue;
    }
    if (skipped) return undefined;
    skipped = true;
  }
  return 1;
}

/**
 * Well-known real packages that sit at distance 1 from a popular name.
 * Checking them as typosquats is noise (NodeGoat lockfile: tmp/tap, csrf/csurf).
 */
const LEGITIMATE_COLLISIONS = new Set([
  'tmp',
  'csrf',
  'crc',
  'extend',
  'utile',
  'foreach',
  'isstream',
  'ansicolors',
  'ansistyles',
  'hpkp',
  'pend',
  'retire',
]);

function hyphenless(name: string): string {
  return name.replace(/-/g, '');
}

export interface TyposquatOptions {
  /** When set, only names the project itself requested (package.json) are checked. */
  directNames?: ReadonlySet<string>;
}

/** Packages whose name is Levenshtein distance 1 from a popular package, and not itself popular. */
export function findTyposquats(
  packages: readonly LockedPackage[],
  options: TyposquatOptions = {},
): TyposquatHit[] {
  const hits: TyposquatHit[] = [];
  for (const pkg of packages) {
    if (pkg.name.length < 4) continue;
    if (popularSet.has(pkg.name)) continue;
    if (LEGITIMATE_COLLISIONS.has(pkg.name)) continue;
    if (options.directNames !== undefined && !options.directNames.has(pkg.name)) continue;
    let best: TyposquatHit | undefined;
    for (const popular of POPULAR_PACKAGES) {
      if (hyphenless(pkg.name) === hyphenless(popular)) continue;
      const distance = levenshteinAtMost1(pkg.name, popular);
      if (distance !== 1) continue;
      if (best === undefined || popular < best.lookalike) {
        best = {
          name: pkg.name,
          version: pkg.version,
          path: pkg.path,
          lookalike: popular,
          distance,
        };
      }
    }
    if (best !== undefined) hits.push(best);
  }
  return hits;
}
