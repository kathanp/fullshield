import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Finding, Severity } from '../../../core/finding.js';
import { compareSemver, rangeSatisfies } from '../semver.js';
import { currentFacts } from './facts.js';
import { npmFinding, npmFlag, npmRow } from './types.js';
import type { NpmDepthInput, NpmDepthRow } from './types.js';

/** Phases 148–167. Registry packuments are read from the cache only. */
const FLAGS = [
  'NPM_REG_INTEGRITY',
  'NPM_REG_TARBALL',
  'NPM_REG_DEPRECATED',
  'NPM_REG_UNPUBLISHED',
  'NPM_REG_NPMUSER',
  'NPM_REG_MAINTAINER',
  'NPM_REG_PROV_ABSENT',
  'NPM_REG_BUILDER',
  'NPM_REG_REPO',
  'NPM_REG_SUBJECT',
  'NPM_REG_TIME',
  'NPM_REG_TRANSITIVE_AGE',
  'NPM_REG_INSTALLSCRIPT',
  'NPM_REG_SIGNATURES',
  'NPM_REG_ENGINES',
  'NPM_REG_DRIFT',
  'NPM_REG_DEPS',
  'NPM_REG_PEER',
  'NPM_REG_BIN',
  'NPM_REG_REPOSITORY',
] as const;

const LOCK_FILE = 'package-lock.json';
const REGISTRY_HOST = 'registry.npmjs.org';

const BUILDER_PATHS: readonly (readonly string[])[] = [
  ['builder', 'id'],
  ['provenance', 'builder', 'id'],
  ['provenance', 'predicate', 'builder', 'id'],
  ['provenance', 'predicate', 'runDetails', 'builder', 'id'],
  ['predicate', 'builder', 'id'],
  ['predicate', 'runDetails', 'builder', 'id'],
];

const REPO_PATHS: readonly (readonly string[])[] = [
  ['repo'],
  ['source'],
  ['provenance', 'source'],
  ['provenance', 'predicate', 'buildDefinition', 'externalParameters', 'workflow', 'repository'],
  ['predicate', 'buildDefinition', 'externalParameters', 'workflow', 'repository'],
  ['provenance', 'predicate', 'materials', '0', 'uri'],
  ['predicate', 'materials', '0', 'uri'],
];

const PAYLOAD_PATHS: readonly (readonly string[])[] = [
  ['bundle', 'dsseEnvelope', 'payload'],
  ['dsseEnvelope', 'payload'],
  ['provenance', 'bundle', 'dsseEnvelope', 'payload'],
  ['provenance', 'dsseEnvelope', 'payload'],
];

const SUBJECT_PATHS: readonly (readonly string[])[] = [
  ['subjectVersion'],
  ['provenance', 'subjectVersion'],
  ['subject'],
  ['provenance', 'subject'],
  ['predicate', 'subject'],
];

const ROWS: readonly (readonly [string, string])[] = [
  ['DEPS-REG-INTEGRITY-001', 'CWE-353'],
  ['DEPS-REG-TARBALL-001', 'CWE-494'],
  ['DEPS-REG-DEPRECATED-001', 'CWE-1104'],
  ['DEPS-REG-UNPUBLISHED-001', 'CWE-829'],
  ['DEPS-REG-NPMUSER-001', 'CWE-829'],
  ['DEPS-REG-MAINTAINER-001', 'CWE-829'],
  ['DEPS-REG-PROV-ABSENT-001', 'CWE-494'],
  ['DEPS-REG-BUILDER-001', 'CWE-494'],
  ['DEPS-REG-REPO-001', 'CWE-829'],
  ['DEPS-REG-SUBJECT-001', 'CWE-345'],
  ['DEPS-REG-TIME-001', 'CWE-345'],
  ['DEPS-REG-AGE-001', 'CWE-1104'],
  ['DEPS-REG-INSTALLSCRIPT-001', 'CWE-829'],
  ['DEPS-REG-SIGNATURES-001', 'CWE-345'],
  ['DEPS-REG-ENGINES-001', 'CWE-1104'],
  ['DEPS-REG-DRIFT-001', 'CWE-1104'],
  ['DEPS-REG-DEPS-001', 'CWE-1104'],
  ['DEPS-REG-PEER-001', 'CWE-829'],
  ['DEPS-REG-BIN-001', 'CWE-22'],
  ['DEPS-REG-REPOSITORY-001', 'CWE-829'],
];

export const laneRows: readonly NpmDepthRow[] = ROWS.map(([ruleId, cwe]) => npmRow(ruleId, cwe));

interface Hit {
  ruleId: string;
  severity: Severity;
  snippet: string;
  title: string;
  message: string;
  remediation: string;
}

interface LockPkg {
  key: string;
  name: string;
  version: string;
  integrity?: string;
  resolved?: string;
  deprecated?: string;
  dev: boolean;
}

interface LockFile {
  entries: LockPkg[];
  directProd: Set<string>;
  directDev: Set<string>;
  names: Set<string>;
  byKey: Map<string, string>;
}

interface Previous {
  maintainers?: string[];
  repo?: string;
  repositoryHost?: string;
}

interface ParsedVersion {
  deprecated?: string;
  npmUser?: string;
  maintainers: string[];
  integrity?: string;
  tarball?: string;
  hasAttestations: boolean;
  signatures: unknown;
  builderIds: string[];
  repos: string[];
  subjectVersions: string[];
  hasInstallScript: boolean;
  enginesNode?: string;
  dependencies: Record<string, string>;
  peerDependencies: Record<string, string>;
  peerOptional: Set<string>;
  bins: string[];
}

type TimeState = 'missing' | 'bad' | 'future' | 'past';

interface ParsedCache {
  version?: ParsedVersion;
  versionsIsObject: boolean;
  versionListed: boolean;
  versionKeys: string[];
  timeRaw?: string;
  timeState: TimeState;
  maintainers: string[];
  repositoryPresent: boolean;
  repositoryHost?: string;
  previous?: Previous;
}

interface ScanCtx {
  now: number;
  ageHours: number;
  builders: ReadonlySet<string>;
  ranges: ReadonlyMap<string, string>;
  enginesNode?: string;
}

interface Subject {
  entry: LockPkg;
  cache: ParsedCache;
  lock: LockFile;
  ctx: ScanCtx;
}

type Ver = readonly [number, number, number];

interface Bound {
  lo: Ver | null;
  loIn: boolean;
  hi: Ver | null;
  hiIn: boolean;
}

const OPEN: Bound = { lo: null, loIn: true, hi: null, hiIn: true };
const ATOM = /^(>=|<=|>|<|\^|~)?v?(\d+\.\d+\.\d+)(?:[-+].*)?$/;

export async function laneFindings(input: NpmDepthInput): Promise<Finding[]> {
  const flags = activeFlags();
  if (flags.size === 0) {return [];}
  const lock = readLock(input.lockTexts[LOCK_FILE]);
  if (lock === undefined || lock.entries.length === 0) {return [];}
  const ctx = await scanCtx(input, flags);
  const findings: Finding[] = [];
  for (const entry of lock.entries) {
    const cache = await loadPackage(input.cacheDir, entry.name, entry.version, ctx.now);
    if (cache === undefined) {continue;}
    findings.push(...allRules(flags, { entry, cache, lock, ctx }));
  }
  return sortUnique(findings);
}

function activeFlags(): Set<string> {
  const on = new Set<string>();
  for (const name of FLAGS) {
    if (npmFlag(name)) {on.add(name);}
  }
  return on;
}

async function scanCtx(input: NpmDepthInput, flags: ReadonlySet<string>): Promise<ScanCtx> {
  const manifest = manifestContext(input.manifestRaw);
  const ageHours = flags.has('NPM_REG_TRANSITIVE_AGE') ? await readAgeHours(input.cwd) : 72;
  const builders = flags.has('NPM_REG_BUILDER') ? loadBuilders() : new Set<string>();
  return { now: Date.now(), ageHours, builders, ranges: manifest.ranges, enginesNode: manifest.enginesNode };
}

function allRules(flags: ReadonlySet<string>, subject: Subject): Finding[] {
  return [...versionRules(flags, subject), ...packumentRules(flags, subject)];
}

function versionRules(flags: ReadonlySet<string>, subject: Subject): Finding[] {
  const version = subject.cache.version;
  if (version === undefined) {return [];}
  return [
    ...gate(flags, 'NPM_REG_INTEGRITY', () => integrityFindings(subject, version)),
    ...gate(flags, 'NPM_REG_TARBALL', () => tarballFindings(subject, version)),
    ...gate(flags, 'NPM_REG_DEPRECATED', () => deprecatedFindings(subject, version)),
    ...gate(flags, 'NPM_REG_NPMUSER', () => npmUserFindings(subject, version)),
    ...gate(flags, 'NPM_REG_PROV_ABSENT', () => provAbsentFindings(subject, version)),
    ...gate(flags, 'NPM_REG_BUILDER', () => builderFindings(subject, version)),
    ...gate(flags, 'NPM_REG_SIGNATURES', () => signatureFindings(subject, version)),
    ...gate(flags, 'NPM_REG_SUBJECT', () => subjectFindings(subject, version)),
    ...gate(flags, 'NPM_REG_REPO', () => attestedRepoFindings(subject, version)),
    ...gate(flags, 'NPM_REG_INSTALLSCRIPT', () => installFindings(subject, version)),
    ...gate(flags, 'NPM_REG_ENGINES', () => enginesFindings(subject, version)),
    ...gate(flags, 'NPM_REG_BIN', () => binFindings(subject, version)),
    ...gate(flags, 'NPM_REG_DEPS', () => depsFindings(subject, version)),
    ...gate(flags, 'NPM_REG_PEER', () => peerFindings(subject, version)),
  ];
}

function packumentRules(flags: ReadonlySet<string>, subject: Subject): Finding[] {
  return [
    ...gate(flags, 'NPM_REG_UNPUBLISHED', () => unpublishedFindings(subject)),
    ...gate(flags, 'NPM_REG_TIME', () => timeFindings(subject)),
    ...gate(flags, 'NPM_REG_TRANSITIVE_AGE', () => ageFindings(subject)),
    ...gate(flags, 'NPM_REG_MAINTAINER', () => maintainerFindings(subject)),
    ...gate(flags, 'NPM_REG_REPOSITORY', () => repositoryFindings(subject)),
    ...gate(flags, 'NPM_REG_DRIFT', () => driftFindings(subject)),
  ];
}

function gate(flags: ReadonlySet<string>, name: string, make: () => Finding[]): Finding[] {
  if (!flags.has(name)) {return [];}
  return make();
}

function integrityFindings(subject: Subject, version: ParsedVersion): Finding[] {
  if (subject.entry.integrity === undefined || version.integrity === undefined) {return [];}
  if (subject.entry.integrity === version.integrity) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-INTEGRITY-001',
    severity: 'critical',
    snippet: spec,
    title: 'Lock integrity does not match the registry',
    message: `${spec} integrity in package-lock.json does not match versions[${subject.entry.version}].dist.integrity.`,
    remediation: 'Regenerate the lockfile from registry.npmjs.org so the integrity matches the packument.',
  })];
}

function tarballFindings(subject: Subject, version: ParsedVersion): Finding[] {
  if (!tarballDiffers(subject.entry.resolved, version.tarball)) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-TARBALL-001',
    severity: 'high',
    snippet: spec,
    title: 'Lock tarball URL does not match the registry',
    message: `${spec} resolved URL does not match dist.tarball on registry.npmjs.org.`,
    remediation: 'Regenerate the lockfile so resolved matches the registry tarball URL.',
  })];
}

function deprecatedFindings(subject: Subject, version: ParsedVersion): Finding[] {
  if (version.deprecated === undefined) {return [];}
  const lockText = subject.entry.deprecated;
  if (lockText !== undefined && lockText.trim().length > 0) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-DEPRECATED-001',
    severity: 'info',
    snippet: spec,
    title: 'Registry deprecation is missing from the lock',
    message: `${spec} is deprecated in the packument (${version.deprecated}) and the lock entry has no deprecated string.`,
    remediation: 'Decide whether to keep this package. FullShield does not name a replacement.',
  })];
}

function npmUserFindings(subject: Subject, version: ParsedVersion): Finding[] {
  const user = version.npmUser;
  if (user === undefined || version.maintainers.length === 0) {return [];}
  if (version.maintainers.includes(user)) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-NPMUSER-001',
    severity: 'medium',
    snippet: `${spec} ${user}`,
    title: 'Publisher is not a maintainer',
    message: `${spec} was published by ${user}, who is not in the packument maintainers.`,
    remediation: 'Confirm the publishing account with the package owner before trusting this version.',
  })];
}

function provAbsentFindings(subject: Subject, version: ParsedVersion): Finding[] {
  if (!isDirectProd(subject)) {return [];}
  if (version.hasAttestations || nonEmptySignatures(version.signatures)) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-PROV-ABSENT-001',
    severity: 'info',
    snippet: spec,
    title: 'Direct dependency has no registry attestation',
    message: `${spec} has no dist.attestations and no dist.signatures. This is not a claim that the package is malicious.`,
    remediation: 'Require provenance before trusting a newly published direct dependency.',
  })];
}

function builderFindings(subject: Subject, version: ParsedVersion): Finding[] {
  const spec = pkgSpec(subject);
  return version.builderIds.filter((id) => !subject.ctx.builders.has(id)).map((id) => hit({
    ruleId: 'DEPS-REG-BUILDER-001',
    severity: 'medium',
    snippet: `${spec} ${id}`,
    title: 'Attestation builder is not in the allowlist',
    message: `${spec} attestation builder ${id} is not listed in models/npm-builders.json.`,
    remediation: 'Add that builder id to the checked-in allowlist only after confirming it from npm documentation.',
  }));
}

function signatureFindings(subject: Subject, version: ParsedVersion): Finding[] {
  if (!Array.isArray(version.signatures) || version.signatures.length > 0) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-SIGNATURES-001',
    severity: 'info',
    snippet: spec,
    title: 'Registry signatures are an empty list',
    message: `${spec} dist.signatures is present and empty.`,
    remediation: 'Treat an empty signature list as unsigned. A missing signatures key is not this finding.',
  })];
}

function subjectFindings(subject: Subject, version: ParsedVersion): Finding[] {
  const mismatch = version.subjectVersions.find((item) => stripV(item) !== stripV(subject.entry.version));
  if (mismatch === undefined) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-SUBJECT-001',
    severity: 'high',
    snippet: `${spec} ${mismatch}`,
    title: 'Attestation subject version does not match the lock',
    message: `${spec} attestation subject version is ${mismatch}.`,
    remediation: 'Do not install a tarball whose attestation subject names a different version.',
  })];
}

function attestedRepoFindings(subject: Subject, version: ParsedVersion): Finding[] {
  const prev = subject.cache.previous?.repo;
  const current = version.repos[0];
  if (prev === undefined || prev.length === 0 || current === undefined) {return [];}
  if (repoIdentity(current) === repoIdentity(prev)) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-REPO-001',
    severity: 'medium',
    snippet: spec,
    title: 'Attested source repository changed',
    message: `${spec} attestation names ${current}, which is not the previously recorded repo ${prev}.`,
    remediation: 'Compare the attested source repository with the previous scan before trusting this version.',
  })];
}

function installFindings(subject: Subject, version: ParsedVersion): Finding[] {
  if (!version.hasInstallScript) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-INSTALLSCRIPT-001',
    severity: 'info',
    snippet: spec,
    title: 'Registry metadata lists an install script',
    message: `${spec} has an install script in the packument. Script bodies are not read here.`,
    remediation: 'Review the package install script before enabling dependency lifecycle scripts.',
  })];
}

function enginesFindings(subject: Subject, version: ParsedVersion): Finding[] {
  const project = subject.ctx.enginesNode;
  const dep = version.enginesNode;
  if (project === undefined || dep === undefined) {return [];}
  if (rangesIntersect(project, dep) !== false) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-ENGINES-001',
    severity: 'medium',
    snippet: spec,
    title: 'Dependency engines do not overlap the project',
    message: `${spec} engines.node ${dep} does not intersect project engines.node ${project}.`,
    remediation: 'Use a release whose engines.node overlaps the project, or change the project engines range.',
  })];
}

function binFindings(subject: Subject, version: ParsedVersion): Finding[] {
  const spec = pkgSpec(subject);
  return version.bins.filter(badBin).map((target) => hit({
    ruleId: 'DEPS-REG-BIN-001',
    severity: 'high',
    snippet: `${spec} ${target}`,
    title: 'Packument bin path escapes the package',
    message: `${spec} bin target ${target} is absolute or contains a parent segment.`,
    remediation: 'Refuse a bin path that leaves the package. A relative path such as bin/cli.js is expected.',
  }));
}

function depsFindings(subject: Subject, version: ParsedVersion): Finding[] {
  const out: Finding[] = [];
  for (const [name, range] of Object.entries(version.dependencies)) {
    const locked = resolveVersion(subject.lock, subject.entry.key, name);
    if (locked === undefined || rangeSatisfies(range, locked) !== false) {continue;}
    const spec = pkgSpec(subject);
    out.push(hit({
      ruleId: 'DEPS-REG-DEPS-001',
      severity: 'medium',
      snippet: `${spec} ${name}@${locked}`,
      title: 'Locked dependency does not satisfy the packument range',
      message: `${spec} depends on ${name}@${range} but the lock has ${locked}.`,
      remediation: 'Reinstall so the lock satisfies the packument range. FullShield does not rewrite the lock.',
    }));
  }
  return out;
}

function peerFindings(subject: Subject, version: ParsedVersion): Finding[] {
  const out: Finding[] = [];
  for (const name of Object.keys(version.peerDependencies)) {
    if (version.peerOptional.has(name) || subject.lock.names.has(name)) {continue;}
    const spec = pkgSpec(subject);
    out.push(hit({
      ruleId: 'DEPS-REG-PEER-001',
      severity: 'medium',
      snippet: `${spec} peer ${name}`,
      title: 'Packument peer is not in the lock',
      message: `${spec} peerDependencies names ${name}, which is absent from the lock.`,
      remediation: 'Add the peer to the project so the lock includes it, or mark that peer optional.',
    }));
  }
  return out;
}

function unpublishedFindings(subject: Subject): Finding[] {
  if (!subject.cache.versionsIsObject || subject.cache.versionListed) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-UNPUBLISHED-001',
    severity: 'critical',
    snippet: spec,
    title: 'Locked version is not in the registry packument',
    message: `${spec} is missing from the cached packument versions object.`,
    remediation: 'Confirm the version still exists on registry.npmjs.org. A missing cache file is not this finding.',
  })];
}

function timeFindings(subject: Subject): Finding[] {
  const state = subject.cache.timeState;
  if (state === 'past') {return [];}
  const spec = pkgSpec(subject);
  const why = state === 'future' ? 'is after the scan clock' : state === 'bad' ? 'does not parse' : 'is missing';
  return [hit({
    ruleId: 'DEPS-REG-TIME-001',
    severity: 'medium',
    snippet: spec,
    title: 'Registry publish time is missing or in the future',
    message: `${spec} packument time ${why}. A past timestamp is not this finding.`,
    remediation: 'Treat a missing or future packument time as unverified. FullShield does not invent one.',
  })];
}

function ageFindings(subject: Subject): Finding[] {
  if (!isTransitiveProd(subject) || !isYoung(subject.cache.timeRaw, subject.ctx.now, subject.ctx.ageHours)) {
    return [];
  }
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-AGE-001',
    severity: 'low',
    snippet: spec,
    title: 'Transitive dependency was published inside the release window',
    message: `${spec} was published inside deps.minReleaseAgeHours. Direct dependencies are not reported here.`,
    remediation: 'Wait out the release window or review the transitive package before deploying.',
  })];
}

function maintainerFindings(subject: Subject): Finding[] {
  const prev = subject.cache.previous?.maintainers;
  if (prev === undefined || !setsDiffer(prev, subject.cache.maintainers)) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-MAINTAINER-001',
    severity: 'medium',
    snippet: spec,
    title: 'Maintainer set changed',
    message: `${spec} maintainers differ from the previous cache.`,
    remediation: 'Compare the maintainer set with the previous scan before trusting this package.',
  })];
}

function repositoryFindings(subject: Subject): Finding[] {
  const prev = subject.cache.previous?.repositoryHost;
  if (prev === undefined || prev.length === 0) {return [];}
  const current = subject.cache.repositoryHost;
  const same = subject.cache.repositoryPresent && current !== undefined && hostKey(current) === hostKey(prev);
  if (same) {return [];}
  const spec = pkgSpec(subject);
  const now = current === undefined || !subject.cache.repositoryPresent ? 'missing' : current;
  return [hit({
    ruleId: 'DEPS-REG-REPOSITORY-001',
    severity: 'info',
    snippet: spec,
    title: 'Package repository host changed',
    message: `${spec} repository host was ${prev} and is now ${now}.`,
    remediation: 'Compare the packument repository host with the previous scan. The repository is not fetched.',
  })];
}

function driftFindings(subject: Subject): Finding[] {
  const range = subject.ctx.ranges.get(subject.entry.name);
  if (range === undefined) {return [];}
  const best = newestInRange(range, subject.cache.versionKeys, subject.entry.version);
  if (best === undefined) {return [];}
  const spec = pkgSpec(subject);
  return [hit({
    ruleId: 'DEPS-REG-DRIFT-001',
    severity: 'info',
    snippet: `${spec} ${best}`,
    title: 'A newer packument version satisfies the manifest range',
    message: `${spec} is older than ${best}, which satisfies ${range} and is a packument version. This is drift, not an advisory.`,
    remediation: 'Update the lock when you want the newer in-range version. FullShield does not rewrite the lock.',
  })];
}

function pkgSpec(subject: Subject): string {
  return `${subject.entry.name}@${subject.entry.version}`;
}

function hit(row: Hit): Finding {
  return npmFinding({ ruleId: row.ruleId, severity: row.severity, file: LOCK_FILE, snippet: row.snippet, title: row.title, message: row.message, remediation: row.remediation });
}

function isDirectProd(subject: Subject): boolean {
  return subject.lock.directProd.has(subject.entry.name) && !subject.entry.dev;
}

function isTransitiveProd(subject: Subject): boolean {
  const { entry, lock } = subject;
  if (lock.directProd.has(entry.name) || lock.directDev.has(entry.name)) {return false;}
  return !entry.dev;
}

function tarballDiffers(lockUrl: string | undefined, registryUrl: string | undefined): boolean {
  if (lockUrl === undefined || registryUrl === undefined) {return false;}
  if (urlHost(lockUrl) !== REGISTRY_HOST || urlHost(registryUrl) !== REGISTRY_HOST) {return false;}
  return stripQuery(lockUrl) !== stripQuery(registryUrl);
}

function stripQuery(url: string): string {
  const query = url.indexOf('?');
  const hash = url.indexOf('#');
  let end = url.length;
  if (query !== -1) {end = Math.min(end, query);}
  if (hash !== -1) {end = Math.min(end, hash);}
  return url.slice(0, end);
}

function badBin(target: string): boolean {
  if (target.startsWith('/') || target.startsWith('\\')) {return true;}
  if (/^[A-Za-z]:[\\/]/.test(target)) {return true;}
  return target.split(/[\\/]/).some((part) => part === '..');
}

function nonEmptySignatures(value: unknown): boolean {
  if (Array.isArray(value)) {return value.length > 0;}
  return isPresent(value);
}

function setsDiffer(left: readonly string[], right: readonly string[]): boolean {
  const a = [...new Set(left)].sort();
  const b = [...new Set(right)].sort();
  if (a.length !== b.length) {return true;}
  return a.some((name, index) => name !== b[index]);
}

function isYoung(raw: string | undefined, now: number, hours: number): boolean {
  if (raw === undefined) {return false;}
  const published = Date.parse(raw);
  if (Number.isNaN(published)) {return false;}
  return (now - published) / 3_600_000 < hours;
}

function newestInRange(range: string, keys: readonly string[], locked: string): string | undefined {
  if (rangeSatisfies(range, '0.0.0') === undefined) {return undefined;}
  let best: string | undefined;
  for (const key of keys) {
    if (rangeSatisfies(range, key) !== true || compareSemver(key, locked) <= 0) {continue;}
    if (best === undefined || compareSemver(key, best) > 0) {best = key;}
  }
  return best;
}

function resolveVersion(lock: LockFile, fromKey: string, dep: string): string | undefined {
  let cursor = fromKey;
  for (let guard = 0; guard < 32; guard += 1) {
    const prefix = cursor.length === 0 ? 'node_modules/' : `${cursor}/node_modules/`;
    const hitVersion = lock.byKey.get(`${prefix}${dep}`);
    if (hitVersion !== undefined) {return hitVersion;}
    if (cursor.length === 0) {return undefined;}
    const idx = cursor.lastIndexOf('/node_modules/');
    cursor = idx === -1 ? '' : cursor.slice(0, idx);
  }
  return undefined;
}

function readLock(text: string | undefined): LockFile | undefined {
  const packages = packagesTable(text);
  if (packages === undefined) {return undefined;}
  const root = asRecord(packages['']) ?? {};
  const directProd = keySet(root.dependencies);
  for (const name of keySet(root.optionalDependencies)) {directProd.add(name);}
  const directDev = keySet(root.devDependencies);
  for (const name of directProd) {directDev.delete(name);}
  const entries: LockPkg[] = [];
  const byKey = new Map<string, string>();
  const names = new Set<string>();
  for (const [key, value] of Object.entries(packages)) {
    const entry = lockEntry(key, value);
    if (entry === undefined) {continue;}
    entries.push(entry);
    byKey.set(key, entry.version);
    names.add(entry.name);
  }
  return { entries, directProd, directDev, names, byKey };
}

function lockEntry(key: string, value: unknown): LockPkg | undefined {
  const name = nameFromKey(key);
  const rec = asRecord(value);
  if (name === undefined || rec === undefined || typeof rec.version !== 'string' || rec.version.length === 0) {
    return undefined;
  }
  return {
    key,
    name,
    version: rec.version,
    integrity: exact(rec.integrity),
    resolved: exact(rec.resolved),
    deprecated: typeof rec.deprecated === 'string' ? rec.deprecated : undefined,
    dev: rec.dev === true,
  };
}

function nameFromKey(key: string): string | undefined {
  const mark = 'node_modules/';
  const idx = key.lastIndexOf(mark);
  if (idx === -1) {return undefined;}
  const name = key.slice(idx + mark.length);
  return name.length > 0 ? name : undefined;
}

function packagesTable(text: string | undefined): Record<string, unknown> | undefined {
  if (text === undefined) {return undefined;}
  try {
    return asRecord(asRecord(JSON.parse(text) as unknown)?.packages);
  } catch {
    return undefined;
  }
}

function keySet(value: unknown): Set<string> {
  const rec = asRecord(value);
  if (rec === undefined) {return new Set();}
  return new Set(Object.keys(rec));
}

function manifestContext(raw: string | undefined): { ranges: Map<string, string>; enginesNode?: string } {
  const doc = parseObject(raw);
  return { ranges: manifestRanges(doc), enginesNode: enginesNode(doc?.engines) };
}

function manifestRanges(doc: Record<string, unknown> | undefined): Map<string, string> {
  const map = new Map<string, string>();
  if (doc === undefined) {return map;}
  for (const field of ['dependencies', 'optionalDependencies', 'devDependencies', 'peerDependencies']) {
    const rec = asRecord(doc[field]);
    if (rec === undefined) {continue;}
    for (const [name, range] of Object.entries(rec)) {
      if (map.has(name) || typeof range !== 'string') {continue;}
      map.set(name, range);
    }
  }
  return map;
}

async function loadPackage(
  cacheDir: string,
  name: string,
  version: string,
  now: number,
): Promise<ParsedCache | undefined> {
  const held = currentFacts()?.packuments.get(name);
  const raw = held !== undefined ? held : await readJson(registryPath(cacheDir, name));
  const packument = packumentOf(raw);
  if (packument === undefined) {return undefined;}
  const inline = previousFrom(asRecord(raw)?.previous);
  const previous = inline ?? await readPrevFile(cacheDir, name);
  return parseCache(packument, version, now, previous);
}

function parseCache(
  packument: Record<string, unknown>,
  version: string,
  now: number,
  previous: Previous | undefined,
): ParsedCache {
  const versions = asRecord(packument.versions);
  const versionRec = versions === undefined ? undefined : asRecord(versions[version]);
  const timeRaw = timeValue(packument, version);
  const repo = repositoryOf(packument);
  return {
    version: versionRec === undefined ? undefined : parseVersion(versionRec, packument),
    versionsIsObject: versions !== undefined,
    versionListed: versionRec !== undefined,
    versionKeys: versions === undefined ? [] : Object.keys(versions),
    timeRaw,
    timeState: classifyTime(timeRaw, now),
    maintainers: namesFrom(packument.maintainers),
    repositoryPresent: repo.present,
    repositoryHost: repo.host,
    previous,
  };
}

function parseVersion(entry: Record<string, unknown>, packument: Record<string, unknown>): ParsedVersion {
  const dist = asRecord(entry.dist);
  const attestations = dist?.attestations;
  const versionMaintainers = namesFrom(entry.maintainers);
  return {
    deprecated: text(entry.deprecated),
    npmUser: npmUserName(entry),
    maintainers: versionMaintainers.length > 0 ? versionMaintainers : namesFrom(packument.maintainers),
    integrity: exact(dist?.integrity),
    tarball: exact(dist?.tarball),
    hasAttestations: isPresent(attestations),
    signatures: dist?.signatures,
    builderIds: builderIds(attestations),
    repos: repoRefs(attestations),
    subjectVersions: subjectVersions(attestations),
    hasInstallScript: installScript(entry),
    enginesNode: enginesNode(entry.engines),
    dependencies: stringMap(entry.dependencies),
    peerDependencies: stringMap(entry.peerDependencies),
    peerOptional: optionalPeers(entry.peerDependenciesMeta),
    bins: binTargets(entry.bin),
  };
}

function timeValue(packument: Record<string, unknown>, version: string): string | undefined {
  const time = asRecord(packument.time);
  const value = time?.[version];
  return typeof value === 'string' ? value : undefined;
}

function classifyTime(raw: string | undefined, now: number): TimeState {
  if (raw === undefined || raw.trim().length === 0) {return 'missing';}
  const ms = Date.parse(raw);
  if (Number.isNaN(ms)) {return 'bad';}
  if (ms > now) {return 'future';}
  return 'past';
}

function repositoryOf(packument: Record<string, unknown>): { present: boolean; host?: string } {
  if (packument.repository === undefined || packument.repository === null) {return { present: false };}
  const url = typeof packument.repository === 'string' ? packument.repository : asRecord(packument.repository)?.url;
  if (typeof url !== 'string' || url.trim().length === 0) {return { present: false };}
  return { present: true, host: hostFromRepository(url.trim()) };
}

function hostFromRepository(url: string): string | undefined {
  const shorthand = shorthandHost(url);
  if (shorthand !== undefined) {return shorthand;}
  const scp = scpHost(url);
  if (scp !== undefined) {return scp;}
  const stripped = url.startsWith('git+') ? url.slice(4) : url;
  return urlHost(stripped);
}

function shorthandHost(url: string): string | undefined {
  if (url.startsWith('github:')) {return 'github.com';}
  if (url.startsWith('gitlab:')) {return 'gitlab.com';}
  if (url.startsWith('bitbucket:')) {return 'bitbucket.com';}
  return undefined;
}

function scpHost(url: string): string | undefined {
  const stripped = url.startsWith('git+') ? url.slice(4) : url;
  if (!stripped.startsWith('git@')) {return undefined;}
  const body = stripped.slice(4);
  const colon = body.indexOf(':');
  const host = colon === -1 ? body : body.slice(0, colon);
  return hostKey(host);
}

function previousFrom(value: unknown): Previous | undefined {
  const rec = asRecord(value);
  if (rec === undefined) {return undefined;}
  const out: Previous = {};
  if (Array.isArray(rec.maintainers)) {
    out.maintainers = rec.maintainers.filter((item): item is string => typeof item === 'string');
  }
  if (typeof rec.repo === 'string') {out.repo = rec.repo;}
  if (typeof rec.repositoryHost === 'string') {out.repositoryHost = rec.repositoryHost;}
  return out;
}

async function readPrevFile(cacheDir: string, name: string): Promise<Previous | undefined> {
  const encoded = name.replaceAll('/', '__');
  return previousFrom(await readJson(join(cacheDir, 'registry', `prev-${encoded}.json`)));
}

function registryPath(cacheDir: string, name: string): string {
  return join(cacheDir, 'registry', `${name.replaceAll('/', '__')}.json`);
}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as unknown;
  } catch {
    return undefined;
  }
}

function packumentOf(raw: unknown): Record<string, unknown> | undefined {
  const doc = asRecord(raw);
  if (doc === undefined) {return undefined;}
  const nested = asRecord(doc.packument);
  if (nested !== undefined) {return nested;}
  if (asRecord(doc.versions) !== undefined) {return doc;}
  return undefined;
}

async function readAgeHours(cwd: string): Promise<number> {
  try {
    const text = await readFile(join(cwd, 'fullshield.config.json'), 'utf8');
    const deps = asRecord(asRecord(JSON.parse(text) as unknown)?.deps);
    const value = deps?.minReleaseAgeHours;
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {return value;}
  } catch {
    // missing config uses the default window
  }
  return 72;
}

function loadBuilders(): Set<string> {
  const out = new Set<string>();
  const list = asRecord(readBuildersFile())?.builders;
  if (!Array.isArray(list)) {return out;}
  for (const item of list) {addBuilderId(out, item);}
  return out;
}

function addBuilderId(out: Set<string>, item: unknown): void {
  if (typeof item === 'string' && item.length > 0) {
    out.add(item);
    return;
  }
  const id = asRecord(item)?.id;
  if (typeof id === 'string' && id.length > 0) {out.add(id);}
}

function readBuildersFile(): unknown {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth += 1) {
    try {
      return JSON.parse(readFileSync(join(dir, 'models', 'npm-builders.json'), 'utf8')) as unknown;
    } catch {
      const parent = dirname(dir);
      if (parent === dir) {break;}
      dir = parent;
    }
  }
  return undefined;
}

function builderIds(attestations: unknown): string[] {
  if (!isPresent(attestations)) {return [];}
  const ids: string[] = [];
  pushBuilders(attestations, ids);
  pushBuilders(decodePayload(attestations), ids);
  return [...new Set(ids)];
}

function pushBuilders(root: unknown, ids: string[]): void {
  const direct = asRecord(root)?.builder;
  if (typeof direct === 'string' && direct.trim().length > 0) {ids.push(direct.trim());}
  for (const path of BUILDER_PATHS) {
    const value = dig(root, path);
    if (typeof value === 'string' && value.trim().length > 0) {ids.push(value.trim());}
  }
}

function repoRefs(attestations: unknown): string[] {
  if (!isPresent(attestations)) {return [];}
  const found = firstString(attestations, REPO_PATHS) ?? firstString(decodePayload(attestations), REPO_PATHS);
  if (found === undefined) {return [];}
  return [found];
}

function subjectVersions(attestations: unknown): string[] {
  if (!isPresent(attestations)) {return [];}
  const out: string[] = [];
  collectSubjects(attestations, out);
  collectSubjects(decodePayload(attestations), out);
  return [...new Set(out)];
}

function collectSubjects(root: unknown, out: string[]): void {
  if (root === undefined || root === null) {return;}
  for (const path of SUBJECT_PATHS) {addSubject(dig(root, path), out);}
}

function addSubject(value: unknown, out: string[]): void {
  if (typeof value === 'string') {
    addSubjectString(value, out);
    return;
  }
  if (!Array.isArray(value)) {return;}
  for (const item of value) {addSubjectItem(item, out);}
}

function addSubjectString(value: string, out: string[]): void {
  const trimmed = value.trim();
  if (/^v?\d+\.\d+\.\d+/.test(trimmed)) {
    out.push(stripV(trimmed));
    return;
  }
  const fromName = versionFromSubjectName(trimmed);
  if (fromName !== undefined) {out.push(fromName);}
}

function addSubjectItem(item: unknown, out: string[]): void {
  if (typeof item === 'string') {
    addSubjectString(item, out);
    return;
  }
  const rec = asRecord(item);
  if (rec === undefined) {return;}
  if (typeof rec.version === 'string' && rec.version.trim().length > 0) {
    out.push(stripV(rec.version.trim()));
    return;
  }
  if (typeof rec.name === 'string') {
    const fromName = versionFromSubjectName(rec.name);
    if (fromName !== undefined) {out.push(fromName);}
  }
}

function versionFromSubjectName(name: string): string | undefined {
  const at = name.lastIndexOf('@');
  if (at <= 0) {return undefined;}
  const ver = name.slice(at + 1);
  if (/^v?\d+\.\d+\.\d+/.test(ver)) {return stripV(ver);}
  return undefined;
}

function stripV(value: string): string {
  return value.startsWith('v') ? value.slice(1) : value;
}

function decodePayload(attestations: unknown): unknown {
  const payload = firstString(attestations, PAYLOAD_PATHS);
  if (payload === undefined) {return undefined;}
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
}

function firstString(root: unknown, paths: readonly (readonly string[])[]): string | undefined {
  for (const path of paths) {
    const value = dig(root, path);
    if (typeof value === 'string' && value.trim().length > 0) {return value.trim();}
  }
  return undefined;
}

function dig(root: unknown, path: readonly string[]): unknown {
  let cur = root;
  for (const key of path) {
    const rec = asIndexable(cur);
    if (rec === undefined) {return undefined;}
    cur = rec[key];
  }
  return cur;
}

function npmUserName(entry: Record<string, unknown>): string | undefined {
  const name = asRecord(entry._npmUser)?.name;
  if (typeof name !== 'string') {return undefined;}
  const trimmed = name.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function namesFrom(value: unknown): string[] {
  if (!Array.isArray(value)) {return [];}
  const out: string[] = [];
  for (const item of value) {
    if (typeof item === 'string' && item.trim().length > 0) {out.push(item.trim());}
    const name = asRecord(item)?.name;
    if (typeof name === 'string' && name.trim().length > 0) {out.push(name.trim());}
  }
  return out;
}

function installScript(entry: Record<string, unknown>): boolean {
  if (entry.hasInstallScript === true) {return true;}
  const scripts = asRecord(entry.scripts);
  if (scripts === undefined) {return false;}
  return ['preinstall', 'install', 'postinstall'].some((key) => typeof scripts[key] === 'string');
}

function enginesNode(value: unknown): string | undefined {
  const node = asRecord(value)?.node;
  return typeof node === 'string' && node.trim().length > 0 ? node.trim() : undefined;
}

function stringMap(value: unknown): Record<string, string> {
  const rec = asRecord(value);
  if (rec === undefined) {return {};}
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(rec)) {
    if (typeof item === 'string') {out[key] = item;}
  }
  return out;
}

function optionalPeers(meta: unknown): Set<string> {
  const rec = asRecord(meta);
  const out = new Set<string>();
  if (rec === undefined) {return out;}
  for (const [name, item] of Object.entries(rec)) {
    if (asRecord(item)?.optional === true) {out.add(name);}
  }
  return out;
}

function binTargets(value: unknown): string[] {
  if (typeof value === 'string') {return [value];}
  const rec = asRecord(value);
  if (rec === undefined) {return [];}
  return Object.values(rec).filter((item): item is string => typeof item === 'string');
}

function isPresent(value: unknown): boolean {
  if (value === null || value === undefined) {return false;}
  if (typeof value === 'string') {return value.length > 0;}
  if (Array.isArray(value)) {return value.length > 0;}
  if (typeof value === 'object') {return Object.keys(value).length > 0;}
  return false;
}

function repoIdentity(raw: string): string {
  let text = raw.trim().replace(/^git\+/i, '');
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  text = text.replace(/^git@/i, '');
  const colon = text.indexOf(':');
  const slash = text.indexOf('/');
  if (colon !== -1 && (slash === -1 || colon < slash)) {
    text = `${text.slice(0, colon)}/${text.slice(colon + 1)}`;
  }
  const at = text.indexOf('@');
  if (at !== -1) {text = text.slice(0, at);}
  return text.replace(/\.git$/i, '').replace(/\/$/, '').toLowerCase().replace(/^www\./, '');
}

function hostKey(host: string): string {
  return host.toLowerCase().replace(/^www\./, '');
}

function urlHost(url: string): string | undefined {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function rangesIntersect(left: string, right: string): boolean | undefined {
  const a = parseUnion(left);
  const b = parseUnion(right);
  if (a === undefined || b === undefined) {return undefined;}
  for (const x of a) {
    for (const y of b) {
      if (intersectBound(x, y) !== undefined) {return true;}
    }
  }
  return false;
}

function parseUnion(range: string): Bound[] | undefined {
  const parts = range.split('||').map((part) => part.trim()).filter((part) => part.length > 0);
  if (parts.length === 0) {return undefined;}
  const bounds: Bound[] = [];
  for (const part of parts) {
    const bound = parseAlternative(part);
    if (bound === undefined) {return undefined;}
    if (bound !== null) {bounds.push(bound);}
  }
  return bounds;
}

function parseAlternative(text: string): Bound | null | undefined {
  if (text === '*' || text === 'x' || text === 'X') {return OPEN;}
  const atoms = text.split(/\s+/).filter((atom) => atom.length > 0);
  if (atoms.length === 0) {return undefined;}
  let acc: Bound = OPEN;
  for (const atom of atoms) {
    const one = atomBound(atom);
    if (one === undefined) {return undefined;}
    const next = intersectBound(acc, one);
    if (next === undefined) {return null;}
    acc = next;
  }
  return acc;
}

function atomBound(atom: string): Bound | undefined {
  const match = ATOM.exec(atom);
  if (match === null || match[2] === undefined) {return undefined;}
  const op = match[1] ?? '=';
  const ver = parseVer(match[2]);
  if (op === '=') {return { lo: ver, loIn: true, hi: ver, hiIn: true };}
  if (op === '>') {return { lo: ver, loIn: false, hi: null, hiIn: false };}
  if (op === '>=') {return { lo: ver, loIn: true, hi: null, hiIn: false };}
  if (op === '<') {return { lo: null, loIn: false, hi: ver, hiIn: false };}
  if (op === '<=') {return { lo: null, loIn: false, hi: ver, hiIn: true };}
  if (op === '^') {return { lo: ver, loIn: true, hi: [ver[0] + 1, 0, 0], hiIn: false };}
  if (op === '~') {return { lo: ver, loIn: true, hi: [ver[0], ver[1] + 1, 0], hiIn: false };}
  return undefined;
}

function intersectBound(a: Bound, b: Bound): Bound | undefined {
  const lo = tighterLo(a, b);
  const hi = tighterHi(a, b);
  if (lo.ver !== null && hi.ver !== null && separated(lo.ver, lo.inc, hi.ver, hi.inc)) {return undefined;}
  return { lo: lo.ver, loIn: lo.inc, hi: hi.ver, hiIn: hi.inc };
}

function tighterLo(a: Bound, b: Bound): { ver: Ver | null; inc: boolean } {
  if (a.lo === null) {return { ver: b.lo, inc: b.loIn };}
  if (b.lo === null) {return { ver: a.lo, inc: a.loIn };}
  const cmp = cmpVer(a.lo, b.lo);
  if (cmp > 0) {return { ver: a.lo, inc: a.loIn };}
  if (cmp < 0) {return { ver: b.lo, inc: b.loIn };}
  return { ver: a.lo, inc: a.loIn && b.loIn };
}

function tighterHi(a: Bound, b: Bound): { ver: Ver | null; inc: boolean } {
  if (a.hi === null) {return { ver: b.hi, inc: b.hiIn };}
  if (b.hi === null) {return { ver: a.hi, inc: a.hiIn };}
  const cmp = cmpVer(a.hi, b.hi);
  if (cmp < 0) {return { ver: a.hi, inc: a.hiIn };}
  if (cmp > 0) {return { ver: b.hi, inc: b.hiIn };}
  return { ver: a.hi, inc: a.hiIn && b.hiIn };
}

function separated(lo: Ver, loIn: boolean, hi: Ver, hiIn: boolean): boolean {
  const cmp = cmpVer(lo, hi);
  if (cmp > 0) {return true;}
  if (cmp < 0) {return false;}
  return !loIn || !hiIn;
}

function parseVer(text: string): Ver {
  const parts = text.split('.').map((part) => Number.parseInt(part, 10));
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

function cmpVer(a: Ver, b: Ver): number {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

function sortUnique(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.id)) {continue;}
    seen.add(finding.id);
    out.push(finding);
  }
  out.sort((a, b) => `${a.ruleId}\n${a.snippet ?? ''}`.localeCompare(`${b.ruleId}\n${b.snippet ?? ''}`));
  return out;
}

function exact(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0) {return undefined;}
  return value;
}

function text(value: unknown): string | undefined {
  if (typeof value !== 'string') {return undefined;}
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function parseObject(raw: string | undefined): Record<string, unknown> | undefined {
  if (raw === undefined) {return undefined;}
  try {
    return asRecord(JSON.parse(raw) as unknown);
  } catch {
    return undefined;
  }
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {return undefined;}
  return value as Record<string, unknown>;
}

function asIndexable(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null) {return undefined;}
  return value as Record<string, unknown>;
}
