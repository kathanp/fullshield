import type { Severity } from '../../../core/finding.js';
import { minFixedVersion } from '../semver.js';

export interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface OsvRange {
  type?: string;
  events?: OsvRangeEvent[];
}

export interface OsvAffectedEntry {
  package?: { ecosystem?: string; name?: string };
  versions?: string[];
  ranges?: OsvRange[];
}

/** Phase 243. GIT and ECOSYSTEM ranges contribute no fixed version when `flagOn`. */
export function fixedVersionForRange(
  affected: readonly OsvAffectedEntry[],
  flagOn: boolean,
): string | undefined {
  if (!flagOn) {return minFixedVersion(affected);}
  const semverOnly = affected.map((entry) => ({
    ranges: (entry.ranges ?? []).filter((range) => range.type === 'SEMVER'),
  }));
  return minFixedVersion(semverOnly);
}

export interface WithdrawnAdvisory {
  id: string;
  withdrawn?: string;
}

function isWithdrawn(value: string | undefined): boolean {
  return value !== undefined && value.trim().length > 0;
}

/** Phase 244. A non-empty `withdrawn` timestamp drops the advisory when `flagOn`. */
export function withoutWithdrawn<T extends WithdrawnAdvisory>(vulns: readonly T[], flagOn: boolean): T[] {
  if (!flagOn) {return [...vulns];}
  return vulns.filter((vuln) => !isWithdrawn(vuln.withdrawn));
}

export interface CvssAdvisory {
  database_specific?: { severity?: string };
  severity?: Array<{ type?: string; score?: string }>;
}

const UNMAPPED_SEVERITY: Severity = 'high';

function wordSeverity(raw: string | undefined): Severity | undefined {
  const value = raw?.trim().toUpperCase();
  if (value === 'CRITICAL') {return 'critical';}
  if (value === 'HIGH') {return 'high';}
  if (value === 'MODERATE' || value === 'MEDIUM') {return 'medium';}
  if (value === 'LOW') {return 'low';}
  return undefined;
}

function numericScore(score: string): number | undefined {
  const trimmed = score.trim();
  if (!/^\d+(?:\.\d+)?$/.test(trimmed)) {return undefined;}
  const n = Number.parseFloat(trimmed);
  return Number.isFinite(n) ? n : undefined;
}

/** Documented cuts: 9–10 critical, 7–8.9 high, 4–6.9 medium, 0.1–3.9 low. */
function scoreBand(score: number): Severity | undefined {
  if (score >= 9 && score <= 10) {return 'critical';}
  if (score >= 7 && score < 9) {return 'high';}
  if (score >= 4 && score < 7) {return 'medium';}
  if (score >= 0.1 && score < 4) {return 'low';}
  return undefined;
}

/**
 * Phase 245. `database_specific.severity` wins.
 * Flag off, CVSS is ignored and an unlabeled advisory stays high.
 */
export function severityFromCvss(vuln: CvssAdvisory, flagOn: boolean): Severity {
  const labeled = wordSeverity(vuln.database_specific?.severity);
  if (labeled !== undefined) {return labeled;}
  if (!flagOn) {return UNMAPPED_SEVERITY;}
  for (const entry of vuln.severity ?? []) {
    const type = entry.type?.toUpperCase();
    if (type !== 'CVSS_V3' && type !== 'CVSS_V4') {continue;}
    if (entry.score === undefined) {continue;}
    const score = numericScore(entry.score);
    if (score === undefined) {continue;}
    const band = scoreBand(score);
    if (band !== undefined) {return band;}
  }
  return UNMAPPED_SEVERITY;
}

export interface AliasAdvisory {
  id: string;
  aliases?: readonly string[];
  affected?: readonly OsvAffectedEntry[];
  references?: string[];
}

function aliasTokens(vuln: AliasAdvisory): Set<string> {
  return new Set([vuln.id, ...(vuln.aliases ?? [])]);
}

function sharesAlias(left: AliasAdvisory, right: AliasAdvisory): boolean {
  const tokens = aliasTokens(right);
  for (const token of aliasTokens(left)) {
    if (tokens.has(token)) {return true;}
  }
  return false;
}

function namesOf(vuln: AliasAdvisory): Set<string> {
  const names = new Set<string>();
  for (const entry of vuln.affected ?? []) {
    const name = entry.package?.name;
    if (name !== undefined && name.length > 0) {names.add(name);}
  }
  return names;
}

function versionsOf(vuln: AliasAdvisory): Set<string> {
  const versions = new Set<string>();
  for (const entry of vuln.affected ?? []) {
    for (const version of entry.versions ?? []) {
      if (version.length > 0) {versions.add(version);}
    }
  }
  return versions;
}

function overlaps(left: Set<string>, right: Set<string>): boolean {
  if (left.size === 0 || right.size === 0) {return true;}
  for (const item of left) {
    if (right.has(item)) {return true;}
  }
  return false;
}

function sameCoordinate(left: AliasAdvisory, right: AliasAdvisory): boolean {
  return overlaps(namesOf(left), namesOf(right)) && overlaps(versionsOf(left), versionsOf(right));
}

function idClass(id: string): number {
  if (id.startsWith('MAL-')) {return 0;}
  if (id.startsWith('GHSA-')) {return 1;}
  if (id.startsWith('CVE-')) {return 2;}
  return 3;
}

function preferId(left: string, right: string): string {
  const classDelta = idClass(left) - idClass(right);
  if (classDelta !== 0) {return classDelta < 0 ? left : right;}
  return left < right ? left : right;
}

function mergeGroup<T extends AliasAdvisory>(group: readonly T[]): T | undefined {
  const first = group[0];
  if (first === undefined) {return undefined;}
  if (group.length === 1) {return first;}
  let winner = first;
  for (const vuln of group) {
    if (preferId(vuln.id, winner.id) === vuln.id) {winner = vuln;}
  }
  const references = [...(winner.references ?? [])];
  const extras = group
    .map((vuln) => vuln.id)
    .filter((id) => id !== winner.id)
    .sort((a, b) => a.localeCompare(b));
  for (const id of extras) {
    if (!references.includes(id)) {references.push(id);}
  }
  return { ...winner, references };
}

/**
 * Phase 246. Shared aliases on the same name@version collapse to one advisory.
 * Survivor order: MAL-, GHSA-, CVE-, then lexicographic. Other ids sit on `references`.
 */
export function dedupeAliases<T extends AliasAdvisory>(
  vulns: readonly T[],
  flagOn: boolean,
): Array<T & { references?: string[] }> {
  if (!flagOn) {return [...vulns];}
  const seen: boolean[] = Array.from({ length: vulns.length }, () => false);
  const out: T[] = [];
  for (let i = 0; i < vulns.length; i++) {
    if (seen[i] === true) {continue;}
    seen[i] = true;
    const group: T[] = [];
    const stack = [i];
    while (stack.length > 0) {
      const current = stack.pop();
      if (current === undefined) {break;}
      const vuln = vulns[current];
      if (vuln === undefined) {continue;}
      group.push(vuln);
      for (let j = 0; j < vulns.length; j++) {
        if (seen[j] === true) {continue;}
        const other = vulns[j];
        if (other === undefined) {continue;}
        if (!sharesAlias(vuln, other) || !sameCoordinate(vuln, other)) {continue;}
        seen[j] = true;
        stack.push(j);
      }
    }
    const merged = mergeGroup(group);
    if (merged !== undefined) {out.push(merged);}
  }
  return out;
}

/** Phase 247. `pkg:npm/<name>@<version>`. A scope slash is `%2F`. No network. */
export function purlFor(name: string, version: string): string {
  return `pkg:npm/${name.replaceAll('/', '%2F')}@${version}`;
}

/**
 * Phase 247. A querybatch that repeats an id keeps the first copy.
 * This does not emit a finding.
 */
export function dedupeAdvisoryIds(ids: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    if (seen.has(id)) {continue;}
    seen.add(id);
    out.push(id);
  }
  return out;
}

export interface CycloneDxPurl {
  purl: string;
  checksum?: { alg: string; content: string };
}

const HASH_ALGS: Readonly<Record<string, string>> = {
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  sha384: 'SHA-384',
  sha512: 'SHA-512',
};

/** Phase 249. Purl plus the CycloneDX hash when an npm integrity string is known. */
export function cyclonedxPurl(name: string, version: string, integrity?: string): CycloneDxPurl {
  const purl = purlFor(name, version);
  if (integrity === undefined || integrity.length === 0) {return { purl };}
  const split = integrity.indexOf('-');
  if (split <= 0) {return { purl };}
  const alg = HASH_ALGS[integrity.slice(0, split).toLowerCase()];
  const content = integrity.slice(split + 1);
  if (alg === undefined || content.length === 0) {return { purl };}
  return { purl, checksum: { alg, content } };
}
