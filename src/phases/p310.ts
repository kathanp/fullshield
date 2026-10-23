import type { UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_VERKEY';

export interface ModelRow {
  id: string;
  appliesTo?: string;
}

export interface Selection {
  row: ModelRow | null;
  versionAssumed: boolean;
  fallback: boolean;
  events: UnsoundEvent[];
}

interface Semver {
  major: number;
  minor: number;
  patch: number;
}

const cache = new Map<string, Selection>();

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function resetVersionCache(): void {
  cache.clear();
}

export function readLockedVersion(lockText: string, resolvedPath: string): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(lockText) as unknown;
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || !('packages' in parsed)) {return null;}
  const packages = parsed.packages;
  if (typeof packages !== 'object' || packages === null) {return null;}
  const row = (packages as Record<string, unknown>)[resolvedPath];
  if (typeof row !== 'object' || row === null || !('version' in row)) {return null;}
  return typeof row.version === 'string' ? row.version : null;
}

export function satisfiesRange(version: string, range: string): boolean {
  const parsed = parseSemver(version);
  if (parsed === null || isGitDep(version)) {return false;}
  return range.trim().split(/\s+/).every((part) => matchesPart(parsed, part));
}

export function selectRow(rows: readonly ModelRow[], version: string | null, packagePath: string): Selection {
  if (!enabled()) {return { row: null, versionAssumed: false, fallback: false, events: [] };}
  const cached = cache.get(packagePath);
  if (cached !== undefined) {return cached;}
  for (const row of rows) {
    if (row.appliesTo === undefined || row.appliesTo.trim() === '') {throw new TypeError('schema: appliesTo required');}
  }
  const selection = choose(rows, version, packagePath);
  cache.set(packagePath, selection);
  return selection;
}

function choose(rows: readonly ModelRow[], version: string | null, packagePath: string): Selection {
  if (version === null || isGitDep(version)) {
    return { row: newest(rows), versionAssumed: true, fallback: false, events: [] };
  }
  const parsed = parseSemver(version);
  if (parsed === null) {
    return { row: newest(rows), versionAssumed: true, fallback: false, events: [] };
  }
  const matches = rows.filter((row) => satisfiesRange(version, row.appliesTo ?? ''));
  if (matches.length > 1) {throw new TypeError('ambiguous appliesTo');}
  const only = matches[0];
  if (only === undefined) {
    return {
      row: null,
      versionAssumed: false,
      fallback: true,
      events: [{ kind: 'unknown-callee', file: packagePath, line: 1, reason: 'version-gap' }],
    };
  }
  return { row: only, versionAssumed: false, fallback: false, events: [] };
}

function newest(rows: readonly ModelRow[]): ModelRow | null {
  let best: ModelRow | null = null;
  let bestMajor = -1;
  for (const row of rows) {
    const digits = (row.appliesTo ?? '').match(/\d+/);
    const major = digits === null ? 0 : Number(digits[0]);
    if (major >= bestMajor) {
      best = row;
      bestMajor = major;
    }
  }
  return best;
}

function isGitDep(version: string): boolean {
  return version.includes('git+') || version.includes('github:') || version.includes('#');
}

function parseSemver(text: string): Semver | null {
  const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(text.trim());
  if (match === null) {return null;}
  return { major: Number(match[1]), minor: Number(match[2] ?? '0'), patch: Number(match[3] ?? '0') };
}

function cmp(left: Semver, right: Semver): number {
  if (left.major !== right.major) {return left.major - right.major;}
  if (left.minor !== right.minor) {return left.minor - right.minor;}
  return left.patch - right.patch;
}

function matchesPart(version: Semver, part: string): boolean {
  if (part === '*' || part === 'x') {return true;}
  if (part.startsWith('^')) {return caret(version, part.slice(1));}
  if (part.startsWith('~')) {return tilde(version, part.slice(1));}
  if (part.startsWith('>=')) {return atLeast(version, part.slice(2));}
  if (part.startsWith('>')) {return above(version, part.slice(1));}
  if (part.startsWith('<=')) {return atMost(version, part.slice(2));}
  if (part.startsWith('<')) {return below(version, part.slice(1));}
  if (part.endsWith('.x') || part.endsWith('.*')) {
    const major = Number(part.split('.')[0]);
    return version.major === major;
  }
  const exact = parseSemver(part);
  return exact !== null && cmp(version, exact) === 0;
}

function caret(version: Semver, text: string): boolean {
  const base = parseSemver(text);
  if (base === null || cmp(version, base) < 0) {return false;}
  if (base.major > 0) {return version.major === base.major;}
  if (base.minor > 0) {return version.major === 0 && version.minor === base.minor;}
  return version.major === 0 && version.minor === 0 && version.patch === base.patch;
}

function tilde(version: Semver, text: string): boolean {
  const base = parseSemver(text);
  return base !== null && version.major === base.major && version.minor === base.minor && cmp(version, base) >= 0;
}

function atLeast(version: Semver, text: string): boolean {
  const base = parseSemver(text);
  return base !== null && cmp(version, base) >= 0;
}

function above(version: Semver, text: string): boolean {
  const base = parseSemver(text);
  return base !== null && cmp(version, base) > 0;
}

function atMost(version: Semver, text: string): boolean {
  const base = parseSemver(text);
  return base !== null && cmp(version, base) <= 0;
}

function below(version: Semver, text: string): boolean {
  const base = parseSemver(text);
  return base !== null && cmp(version, base) < 0;
}
