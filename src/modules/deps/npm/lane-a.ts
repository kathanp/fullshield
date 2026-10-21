import { readFile } from 'node:fs/promises';
import { builtinModules } from 'node:module';
import { join, relative, resolve, sep } from 'node:path';

import type { Finding } from '../../../core/finding.js';
import { parseLockfile } from '../lockfile.js';
import { isProductionSource } from '../reachability.js';
import { npmFinding, npmFlag, npmRow, type NpmDepthInput, type NpmDepthRow } from './types.js';

const SHRINKWRAP_ONLY = 'DEPS-SHRINKWRAP-001';
const SHRINKWRAP_DIFF = 'DEPS-SHRINKWRAP-002';
const LOCKVER = 'DEPS-LOCKVER-001';
const MULTLOCK = 'DEPS-MULTLOCK-001';
const ROOTVER = 'DEPS-ROOTVER-001';
const NONSEMVER = 'DEPS-NONSEMVER-001';
const NORESOLVED = 'DEPS-NORESOLVED-001';
const RESOLVED_HOST = 'DEPS-RESOLVED-HOST-001';
const RESOLVED_HTTP = 'DEPS-RESOLVED-HTTP-001';
const NOINTEGRITY = 'DEPS-NOINTEGRITY-001';
const WEAKINTEGRITY = 'DEPS-WEAKINTEGRITY-001';
const BADINTEGRITY = 'DEPS-BADINTEGRITY-001';
const LINKDEP = 'DEPS-LINKDEP-001';
const GITDEP = 'DEPS-GITDEP-001';
const NPMALIAS = 'DEPS-NPMALIAS-001';
const BUNDLED = 'DEPS-BUNDLED-001';
const PEER = 'DEPS-PEER-UNDECLARED-001';
const OPTIONAL = 'DEPS-OPTIONAL-IMPORT-001';
const LOCKPATH = 'DEPS-LOCKPATH-001';
const LOCKOMIT = 'DEPS-LOCKOMIT-001';
const DEVPROD = 'DEPS-DEV-PROD-EDGE-001';

const FLAGS = [
  'NPM_SHRINKWRAP',
  'NPM_LOCKVER',
  'NPM_MULTLOCK',
  'NPM_ROOTVER',
  'NPM_NONSEMVER',
  'NPM_NORESOLVED',
  'NPM_RESOLVED_HOST',
  'NPM_RESOLVED_HTTP',
  'NPM_NOINTEGRITY',
  'NPM_WEAKINTEGRITY',
  'NPM_BADINTEGRITY',
  'NPM_LINKDEP',
  'NPM_GITDEP',
  'NPM_ALIAS',
  'NPM_BUNDLED',
  'NPM_PEER',
  'NPM_OPTIONAL',
  'NPM_LOCKPATH',
  'NPM_LOCKOMIT',
  'NPM_DEVPROD',
] as const;

const LOCK_NAMES = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
] as const;

const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json'] as const;

const GIT_PREFIXES = [
  'git:',
  'git+https:',
  'git+ssh:',
  'git+http:',
  'github:',
  'gitlab:',
  'bitbucket:',
  'gist:',
] as const;

const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

const ALIAS = /^npm:(@[^@/\s]+\/[^@/\s]+|[^@/\s]+)@(.+)$/;

const BUILTINS = new Set(builtinModules.flatMap((name) => [name, name.replace(/^node:/, '')]));

const SOURCE = /\.[cm]?[jt]sx?$/;

export const laneRows: readonly NpmDepthRow[] = [
  npmRow(SHRINKWRAP_ONLY, 'CWE-829'),
  npmRow(SHRINKWRAP_DIFF, 'CWE-436'),
  npmRow(LOCKVER, 'CWE-1104'),
  npmRow(MULTLOCK, 'CWE-436'),
  npmRow(ROOTVER, 'CWE-436'),
  npmRow(NONSEMVER, 'CWE-1104'),
  npmRow(NORESOLVED, 'CWE-829'),
  npmRow(RESOLVED_HOST, 'CWE-494'),
  npmRow(RESOLVED_HTTP, 'CWE-319'),
  npmRow(NOINTEGRITY, 'CWE-353'),
  npmRow(WEAKINTEGRITY, 'CWE-328'),
  npmRow(BADINTEGRITY, 'CWE-353'),
  npmRow(LINKDEP, 'CWE-829'),
  npmRow(GITDEP, 'CWE-829'),
  npmRow(NPMALIAS, 'CWE-829'),
  npmRow(BUNDLED, 'CWE-829'),
  npmRow(PEER, 'CWE-829'),
  npmRow(OPTIONAL, 'CWE-703'),
  npmRow(LOCKPATH, 'CWE-22'),
  npmRow(LOCKOMIT, 'CWE-829'),
  npmRow(DEVPROD, 'CWE-829'),
];

interface LockEntry {
  version?: unknown;
  resolved?: unknown;
  integrity?: unknown;
  link?: unknown;
  dev?: unknown;
  optional?: unknown;
  peer?: unknown;
  inBundle?: unknown;
  bundled?: unknown;
  dependencies?: unknown;
  devDependencies?: unknown;
  optionalDependencies?: unknown;
  peerDependencies?: unknown;
  requires?: unknown;
  license?: unknown;
  name?: unknown;
  bundleDependencies?: unknown;
  bundledDependencies?: unknown;
}

interface NpmLock {
  lockfileVersion?: unknown;
  packages?: Record<string, LockEntry>;
  dependencies?: Record<string, LockEntry>;
  bundleDependencies?: unknown;
  bundledDependencies?: unknown;
  peerDependencies?: unknown;
}

interface DepNode {
  label: string;
  dev: boolean;
  deps: string[];
}

export async function laneFindings(input: NpmDepthInput): Promise<Finding[]> {
  if (!FLAGS.some((name) => npmFlag(name))) {return [];}
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const manifest = parseObject(input.manifestRaw);
  const locks = npmLocks(input);
  const present = LOCK_NAMES.filter((name) => hasRoot(input.files, name));

  if (npmFlag('NPM_SHRINKWRAP')) {
    const shrink = input.lockTexts['npm-shrinkwrap.json'];
    const pkgLock = input.lockTexts['package-lock.json'];
    const onlyShrink = present.length === 1 && present[0] === 'npm-shrinkwrap.json';
    if (onlyShrink && shrink !== undefined) {
      push(findings, seen, npmFinding(
        SHRINKWRAP_ONLY,
        'info',
        'npm-shrinkwrap.json',
        'npm-shrinkwrap.json',
        'npm-shrinkwrap.json is the only lockfile',
        'npm-shrinkwrap.json is the only lockfile. It is parsed with the package-lock parser.',
        'Commit package-lock.json as the project lockfile, or keep a single shrinkwrap on purpose.',
      ));
    }
    if (shrink !== undefined && pkgLock !== undefined && nameSetsDiffer(shrink, pkgLock)) {
      push(findings, seen, npmFinding(
        SHRINKWRAP_DIFF,
        'high',
        'npm-shrinkwrap.json',
        'npm-shrinkwrap.json package-lock.json',
        'Shrinkwrap and package-lock name@version sets differ',
        'npm-shrinkwrap.json and package-lock.json list different name@version sets.',
        'Delete one lockfile, or regenerate both from the same install so the name@version sets match.',
      ));
    }
  }

  if (npmFlag('NPM_MULTLOCK') && present.length >= 2) {
    const names = present.join(', ');
    push(findings, seen, npmFinding(
      MULTLOCK,
      'medium',
      present[0] ?? 'package-lock.json',
      names,
      'Multiple lockfiles at the repo root',
      `Multiple lockfiles at the repo root: ${names}.`,
      'Keep one lockfile. This check does not choose which file wins.',
    ));
  }

  const bundleDeclared = bundleNames(manifest, locks);
  const peerDeclared = peerNames(manifest, locks);
  const peers = new Set<string>();
  const optionals = new Set<string>();
  const devEdges = new Map<string, Set<string>>();
  const rootDeps = new Set<string>();

  for (const lock of locks) {
    if (npmFlag('NPM_LOCKVER')) {pushLockver(findings, seen, lock);}
    if (npmFlag('NPM_ROOTVER')) {pushRootver(findings, seen, lock, manifest);}
    for (const name of rootDepNames(lock.json)) {rootDeps.add(name);}
    inspectLock(lock, findings, seen, input.cwd, bundleDeclared, peers, optionals, devEdges);
  }

  if (manifest !== undefined) {
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const { name, spec } of stringDeps(manifest[field])) {
        pushSpec(findings, seen, 'package.json', name, spec, input.cwd);
      }
    }
  }

  if (npmFlag('NPM_LOCKOMIT') && locks.length > 0 && manifest !== undefined) {
    for (const name of Object.keys(record(manifest.dependencies))) {
      if (rootDeps.has(name)) {continue;}
      push(findings, seen, npmFinding(
        LOCKOMIT,
        'high',
        'package.json',
        name,
        `Manifest dependency ${name} is absent from the lock root`,
        `package.json dependencies names ${name}, which is absent from packages[""].dependencies and from the top-level dependencies object.`,
        `Regenerate the lockfile so ${name} is a root dependency entry.`,
      ));
    }
  }

  if (npmFlag('NPM_DEVPROD')) {
    for (const [child, parents] of [...devEdges.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      const listed = [...parents].sort().join(', ');
      const file = locks[0]?.file ?? 'package-lock.json';
      push(findings, seen, npmFinding(
        DEVPROD,
        'medium',
        file,
        `${listed} > ${child}`,
        `Dev package ${child} is required by production`,
        `${child} is marked dev and is required by ${listed}.`,
        `Move ${child} out of the production graph, or stop marking it dev.`,
      ));
    }
  }

  if ((npmFlag('NPM_PEER') || npmFlag('NPM_OPTIONAL')) && (peers.size > 0 || optionals.size > 0)) {
    const sources = await readSources(input);
    for (const source of sources) {
      if (!isProductionSource(source.file)) {continue;}
      for (const site of importSites(source.text)) {
        if (npmFlag('NPM_PEER') && peers.has(site.name) && !peerDeclared.has(site.name)) {
          const finding = npmFinding(
            PEER,
            'medium',
            source.file,
            site.name,
            `Undeclared peer ${site.name} is imported`,
            `${source.file} imports ${site.name}, which the lock marks peer and the root peerDependencies does not name.`,
            `Add ${site.name} to peerDependencies, or stop importing it.`,
          );
          finding.line = site.line;
          push(findings, seen, finding);
        }
        if (npmFlag('NPM_OPTIONAL') && optionals.has(site.name) && !site.guarded) {
          const finding = npmFinding(
            OPTIONAL,
            'low',
            source.file,
            site.name,
            `Optional dependency ${site.name} is imported outside try/catch`,
            `${source.file} imports ${site.name}, which the lock marks optional, and the import is not inside a try/catch.`,
            `Import ${site.name} inside try/catch, or make the dependency required.`,
          );
          finding.line = site.line;
          push(findings, seen, finding);
        }
      }
    }
  }

  findings.sort((a, b) => {
    const ak = `${a.ruleId}\0${a.file ?? ''}\0${a.line ?? 0}\0${a.snippet ?? ''}`;
    const bk = `${b.ruleId}\0${b.file ?? ''}\0${b.line ?? 0}\0${b.snippet ?? ''}`;
    return ak.localeCompare(bk);
  });
  return findings;
}

function push(findings: Finding[], seen: Set<string>, finding: Finding): void {
  const key = `${finding.ruleId}\0${finding.file ?? ''}\0${finding.snippet ?? ''}\0${finding.severity}`;
  if (seen.has(key)) {return;}
  seen.add(key);
  findings.push(finding);
}

function hasRoot(files: readonly string[], name: string): boolean {
  return files.some((file) => file.replace(/\\/g, '/') === name);
}

function parseObject(text: string | undefined): Record<string, unknown> | undefined {
  if (text === undefined) {return undefined;}
  try {
    const value = JSON.parse(text) as unknown;
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function npmLocks(input: NpmDepthInput): Array<{ file: string; text: string; json: NpmLock }> {
  const out: Array<{ file: string; text: string; json: NpmLock }> = [];
  for (const file of NPM_LOCKS) {
    const text = input.lockTexts[file];
    const json = parseObject(text);
    if (text === undefined || json === undefined) {continue;}
    out.push({ file, text, json });
  }
  return out;
}

function nameSetsDiffer(left: string, right: string): boolean {
  const a = new Set(parseLockfile('package-lock.json', left).map((pkg) => `${pkg.name}@${pkg.version}`));
  const b = new Set(parseLockfile('package-lock.json', right).map((pkg) => `${pkg.name}@${pkg.version}`));
  if (a.size !== b.size) {return true;}
  for (const item of a) {
    if (!b.has(item)) {return true;}
  }
  return false;
}

function record(value: unknown): Record<string, unknown> {
  if (value === undefined || value === null || typeof value !== 'object' || Array.isArray(value)) {return {};}
  return value as Record<string, unknown>;
}

function stringDeps(value: unknown): Array<{ name: string; spec: string }> {
  const out: Array<{ name: string; spec: string }> = [];
  for (const [name, spec] of Object.entries(record(value))) {
    if (typeof spec === 'string') {out.push({ name, spec });}
  }
  return out;
}

function nameList(value: unknown): string[] {
  if (!Array.isArray(value)) {return [];}
  return value.filter((item): item is string => typeof item === 'string');
}

function bundleNames(
  manifest: Record<string, unknown> | undefined,
  locks: Array<{ json: NpmLock }>,
): Set<string> {
  const names = new Set<string>();
  const add = (value: unknown): void => {
    for (const name of nameList(value)) {names.add(name);}
  };
  if (manifest !== undefined) {
    add(manifest.bundleDependencies);
    add(manifest.bundledDependencies);
  }
  for (const lock of locks) {
    add(lock.json.bundleDependencies);
    add(lock.json.bundledDependencies);
    const root = lock.json.packages?.[''];
    if (root !== undefined) {
      add(root.bundleDependencies);
      add(root.bundledDependencies);
    }
  }
  return names;
}

function peerNames(
  manifest: Record<string, unknown> | undefined,
  locks: Array<{ json: NpmLock }>,
): Set<string> {
  const names = new Set<string>();
  const add = (value: unknown): void => {
    for (const name of Object.keys(record(value))) {names.add(name);}
  };
  if (manifest !== undefined) {add(manifest.peerDependencies);}
  for (const lock of locks) {
    add(lock.json.peerDependencies);
    add(lock.json.packages?.['']?.peerDependencies);
  }
  return names;
}

function rootDepNames(lock: NpmLock): Set<string> {
  const names = new Set<string>();
  for (const name of Object.keys(record(lock.packages?.['']?.dependencies))) {names.add(name);}
  for (const name of Object.keys(record(lock.dependencies))) {names.add(name);}
  return names;
}

function pushLockver(
  findings: Finding[],
  seen: Set<string>,
  lock: { file: string; json: NpmLock },
): void {
  const value = lock.json.lockfileVersion;
  if (typeof value === 'number' && Number.isFinite(value) && value !== 1 && value <= 3) {return;}
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed) && parsed !== 1 && parsed <= 3) {return;}
  }
  const shown = value === undefined ? 'missing' : typeof value === 'string' || typeof value === 'number' ? String(value) : 'missing';
  push(findings, seen, npmFinding(
    LOCKVER,
    'medium',
    lock.file,
    `lockfileVersion ${shown}`,
    `Unsupported lockfileVersion ${shown}`,
    `lockfileVersion is ${shown}. Supported npm lockfile versions are 2 and 3.`,
    'Regenerate the lockfile with a current npm so lockfileVersion is 2 or 3.',
  ));
}

function pushRootver(
  findings: Finding[],
  seen: Set<string>,
  lock: { file: string; json: NpmLock },
  manifest: Record<string, unknown> | undefined,
): void {
  const root = lock.json.packages?.[''];
  if (root === undefined || typeof root.version !== 'string' || manifest === undefined) {return;}
  const manifestVersion = manifest.version;
  if (typeof manifestVersion === 'string' && manifestVersion === root.version) {return;}
  const shown = typeof manifestVersion === 'string' ? manifestVersion : '(none)';
  push(findings, seen, npmFinding(
    ROOTVER,
    'medium',
    lock.file,
    `${root.version} != ${shown}`,
    'Root package version differs from the lockfile',
    `packages[""].version is ${root.version} and package.json version is ${shown}.`,
    'Regenerate the lockfile so the root version matches package.json. Workspace package versions are not this check.',
  ));
}

function inspectLock(
  lock: { file: string; json: NpmLock },
  findings: Finding[],
  seen: Set<string>,
  cwd: string,
  bundleDeclared: Set<string>,
  peers: Set<string>,
  optionals: Set<string>,
  devEdges: Map<string, Set<string>>,
): void {
  const packages = lock.json.packages;
  const nodes: DepNode[] = [];
  if (packages !== undefined && typeof packages === 'object') {
    for (const [key, entry] of Object.entries(packages)) {
      if (!isEntry(entry)) {continue;}
      const name = key === '' ? undefined : nameFromKey(key);
      visitEntry(lock.file, key, entry, true, name, findings, seen, cwd, bundleDeclared, peers, optionals);
      nodes.push({
        label: key === '' ? 'root' : (name ?? key),
        dev: entry.dev === true,
        deps: requirementNames(entry),
      });
      for (const { name: depName, spec } of stringDeps(entry.dependencies)) {
        pushSpec(findings, seen, lock.file, depName, spec, cwd);
      }
      for (const { name: depName, spec } of stringDeps(entry.optionalDependencies)) {
        pushSpec(findings, seen, lock.file, depName, spec, cwd);
      }
      for (const { name: depName, spec } of stringDeps(entry.peerDependencies)) {
        pushSpec(findings, seen, lock.file, depName, spec, cwd);
      }
      if (key === '') {
        for (const { name: depName, spec } of stringDeps(entry.devDependencies)) {
          pushSpec(findings, seen, lock.file, depName, spec, cwd);
        }
      }
    }
  } else if (lock.json.dependencies !== undefined) {
    walkDeps(lock.json.dependencies, '', lock.file, findings, seen, cwd, bundleDeclared, peers, optionals, nodes);
  }
  addDevEdges(nodes, devEdges);
}

function walkDeps(
  deps: Record<string, LockEntry>,
  prefix: string,
  file: string,
  findings: Finding[],
  seen: Set<string>,
  cwd: string,
  bundleDeclared: Set<string>,
  peers: Set<string>,
  optionals: Set<string>,
  nodes: DepNode[],
): void {
  for (const [name, entry] of Object.entries(deps)) {
    if (!isEntry(entry)) {continue;}
    const key = prefix === '' ? `node_modules/${name}` : `${prefix}/node_modules/${name}`;
    visitEntry(file, key, entry, false, name, findings, seen, cwd, bundleDeclared, peers, optionals);
    nodes.push({ label: name, dev: entry.dev === true, deps: requirementNames(entry) });
    const nested = entry.dependencies;
    if (isRecord(nested)) {
      walkDeps(nested as Record<string, LockEntry>, key, file, findings, seen, cwd, bundleDeclared, peers, optionals, nodes);
    }
  }
}

function visitEntry(
  file: string,
  key: string,
  entry: LockEntry,
  fromPackages: boolean,
  name: string | undefined,
  findings: Finding[],
  seen: Set<string>,
  cwd: string,
  bundleDeclared: Set<string>,
  peers: Set<string>,
  optionals: Set<string>,
): void {
  const label = name ?? key;
  if (typeof entry.version === 'string') {
    pushVersion(findings, seen, file, label, entry.version);
    pushSpec(findings, seen, file, label, entry.version, cwd);
  }
  if (typeof entry.resolved === 'string') {
    pushResolved(findings, seen, file, label, entry.resolved, entry.integrity, cwd);
  }
  if (fromPackages && npmFlag('NPM_LOCKPATH') && key !== '' && (!key.startsWith('node_modules/') || key.includes('..'))) {
    push(findings, seen, npmFinding(
      LOCKPATH,
      'high',
      file,
      key,
      'Lockfile packages key has an unexpected shape',
      `packages key ${key} is not "" and does not stay under node_modules/.`,
      'Regenerate the lockfile so every packages key is "" or starts with node_modules/ and contains no .. segment.',
    ));
  }
  if (fromPackages && npmFlag('NPM_NORESOLVED')) {
    pushMissingResolved(findings, seen, file, key, entry);
  }
  if (npmFlag('NPM_BUNDLED') && name !== undefined && (entry.inBundle === true || entry.bundled === true) && !bundleDeclared.has(name)) {
    push(findings, seen, npmFinding(
      BUNDLED,
      'medium',
      file,
      name,
      `Bundled package ${name} is not in the root bundle list`,
      `${name} is marked inBundle or bundled, and the root bundleDependencies / bundledDependencies array does not name it.`,
      `Add ${name} to bundleDependencies, or remove the bundled flag and depend on it normally.`,
    ));
  }
  if (name !== undefined && entry.peer === true) {peers.add(name);}
  if (name !== undefined && entry.optional === true) {optionals.add(name);}
  if (typeof entry.integrity === 'string') {
    pushIntegrity(findings, seen, file, label, entry.integrity);
  }
}

/** Production edges. Root devDependencies are the dev set and are not included. */
function requirementNames(entry: LockEntry): string[] {
  return [
    ...Object.keys(record(entry.dependencies)),
    ...Object.keys(record(entry.optionalDependencies)),
    ...Object.keys(record(entry.requires)),
  ];
}

function addDevEdges(nodes: DepNode[], devEdges: Map<string, Set<string>>): void {
  if (!npmFlag('NPM_DEVPROD')) {return;}
  const devNames = new Set(nodes.filter((node) => node.dev && node.label !== 'root').map((node) => node.label));
  for (const node of nodes) {
    if (node.dev) {continue;}
    for (const dep of node.deps) {
      if (!devNames.has(dep)) {continue;}
      const parents = devEdges.get(dep) ?? new Set<string>();
      parents.add(node.label);
      devEdges.set(dep, parents);
    }
  }
}

/**
 * A packages row that only stores version, name, and license has no install
 * record. Missing `resolved` is reported for every other semver packages row
 * except the root and link: workspace rows.
 */
function licenseMetadataOnly(entry: LockEntry): boolean {
  const keys = Object.keys(entry);
  if (!keys.includes('license')) {return false;}
  return keys.every((key) => key === 'version' || key === 'license' || key === 'name');
}

function pushMissingResolved(
  findings: Finding[],
  seen: Set<string>,
  file: string,
  key: string,
  entry: LockEntry,
): void {
  if (key === '') {return;}
  if (entry.link === true) {return;}
  if (typeof entry.resolved === 'string' && entry.resolved.startsWith('link:')) {return;}
  if (typeof entry.resolved === 'string' && entry.resolved.trim() !== '') {return;}
  if (typeof entry.version !== 'string' || !SEMVER.test(entry.version)) {return;}
  if (licenseMetadataOnly(entry)) {return;}
  const label = nameFromKey(key) ?? key;
  push(findings, seen, npmFinding(
    NORESOLVED,
    'medium',
    file,
    `${label}@${entry.version}`,
    `Locked ${label}@${entry.version} has no resolved URL`,
    `${key} has semver version ${entry.version} and no resolved URL.`,
    'Regenerate the lockfile so this package has a resolved tarball URL.',
  ));
}

function pushVersion(
  findings: Finding[],
  seen: Set<string>,
  file: string,
  label: string,
  version: string,
): void {
  if (!npmFlag('NPM_NONSEMVER') || SEMVER.test(version)) {return;}
  push(findings, seen, npmFinding(
    NONSEMVER,
    'medium',
    file,
    `${label}@${version}`,
    `Locked version ${version} is not semver`,
    `${label} is locked at ${version === '' ? 'an empty version' : version}, which is not MAJOR.MINOR.PATCH with an optional prerelease.`,
    'Lock a MAJOR.MINOR.PATCH release. The locked text is not rewritten into a semver.',
  ));
}

function pushSpec(
  findings: Finding[],
  seen: Set<string>,
  file: string,
  requested: string,
  spec: string,
  cwd: string,
): void {
  const trimmed = spec.trim();
  if (trimmed.startsWith('file:') || trimmed.startsWith('link:')) {
    pushLink(findings, seen, file, trimmed, cwd);
  }
  if (isGit(trimmed)) {pushGit(findings, seen, file, trimmed);}
  if (!npmFlag('NPM_ALIAS')) {return;}
  const match = ALIAS.exec(trimmed);
  const target = match?.[1];
  const version = match?.[2];
  if (target === undefined || version === undefined || target === requested) {return;}
  push(findings, seen, npmFinding(
    NPMALIAS,
    'medium',
    file,
    requested,
    `npm alias ${requested} points at ${target}@${version}`,
    `${requested} uses npm: and the target is ${target}@${version}.`,
    `Depend on ${target} directly, or keep the alias only when the names match.`,
  ));
}

function pushResolved(
  findings: Finding[],
  seen: Set<string>,
  file: string,
  label: string,
  resolved: string,
  integrity: unknown,
  cwd: string,
): void {
  pushSpec(findings, seen, file, label, resolved, cwd);
  let url: URL | undefined;
  try {
    url = new URL(resolved);
  } catch {
    url = undefined;
  }
  if (url === undefined) {return;}
  if (url.protocol === 'http:' && npmFlag('NPM_RESOLVED_HTTP')) {
    push(findings, seen, npmFinding(
      RESOLVED_HTTP,
      'high',
      file,
      `${label} ${resolved}`,
      'Lockfile tarball URL is cleartext http',
      `${label} resolved ${resolved} uses http:.`,
      'Use an https://registry.npmjs.org tarball URL.',
    ));
  }
  if (url.protocol === 'https:' && url.hostname !== 'registry.npmjs.org' && npmFlag('NPM_RESOLVED_HOST')) {
    push(findings, seen, npmFinding(
      RESOLVED_HOST,
      'high',
      file,
      `${label} ${url.hostname}`,
      'Lockfile tarball host is not the npm registry',
      `${label} resolved host is ${url.hostname}.`,
      'Resolve the package from https://registry.npmjs.org.',
    ));
  }
  const blankIntegrity = typeof integrity !== 'string' || integrity.trim() === '';
  if (url.protocol === 'https:' && url.hostname === 'registry.npmjs.org' && blankIntegrity && npmFlag('NPM_NOINTEGRITY')) {
    push(findings, seen, npmFinding(
      NOINTEGRITY,
      'high',
      file,
      `${label} ${resolved}`,
      'Registry tarball has no integrity',
      `${label} resolved ${resolved} and integrity is missing or empty.`,
      'Regenerate the lockfile so this entry has a sha512 integrity.',
    ));
  }
}

function pushIntegrity(
  findings: Finding[],
  seen: Set<string>,
  file: string,
  label: string,
  integrity: string,
): void {
  const trimmed = integrity.trim();
  if (trimmed === '') {return;}
  const kind = classifyIntegrity(trimmed);
  if (kind.weak && npmFlag('NPM_WEAKINTEGRITY')) {
    push(findings, seen, npmFinding(
      WEAKINTEGRITY,
      'medium',
      file,
      `${label} ${trimmed}`,
      'Lockfile integrity uses a weak hash',
      `${label} integrity uses sha1 or sha256. The registry algorithm is sha512.`,
      'Regenerate the lockfile so integrity starts with sha512-.',
    ));
  }
  if (kind.bad && npmFlag('NPM_BADINTEGRITY')) {
    push(findings, seen, npmFinding(
      BADINTEGRITY,
      'high',
      file,
      `${label} ${trimmed}`,
      'Lockfile integrity is not a valid hash',
      `${label} integrity is not algo-base64 for sha1, sha256, or sha512, or the base64 does not decode.`,
      'Regenerate the lockfile so integrity is a sha512- base64 value.',
    ));
  }
}

function classifyIntegrity(integrity: string): { weak: boolean; bad: boolean } {
  let weak = false;
  let bad = false;
  for (const token of integrity.split(/\s+/)) {
    if (token === '') {continue;}
    const match = /^(sha1|sha256|sha512)-([A-Za-z0-9+/]*={0,2})$/.exec(token);
    const algo = match?.[1];
    const payload = match?.[2];
    if (algo === undefined || payload === undefined || !base64Decodes(payload)) {
      bad = true;
      continue;
    }
    if (algo === 'sha1' || algo === 'sha256') {weak = true;}
  }
  return { weak, bad };
}

function base64Decodes(value: string): boolean {
  if (value.length === 0 || value.length % 4 !== 0) {return false;}
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/.test(value)) {
    return false;
  }
  return Buffer.from(value, 'base64').length > 0;
}

function pushLink(
  findings: Finding[],
  seen: Set<string>,
  file: string,
  spec: string,
  cwd: string,
): void {
  if (!npmFlag('NPM_LINKDEP')) {return;}
  const severity = escapesRepo(cwd, spec) ? 'high' : 'medium';
  const kind = spec.startsWith('file:') ? 'file' : 'link';
  push(findings, seen, npmFinding(
    LINKDEP,
    severity,
    file,
    spec,
    severity === 'high' ? `${kind}: dependency escapes the repo root` : `${kind}: dependency`,
    severity === 'high'
      ? `${spec} escapes the repo root.`
      : `${spec} is a ${kind} dependency.`,
    severity === 'high'
      ? 'Keep the path inside the repo, or depend on a registry release.'
      : 'Prefer a registry release with an integrity hash.',
  ));
}

function escapesRepo(cwd: string, spec: string): boolean {
  const raw = spec.replace(/^(?:file|link):/, '');
  if (!raw.includes('..')) {return false;}
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    decoded = raw;
  }
  const abs = resolve(cwd, decoded);
  const rel = relative(cwd, abs);
  return rel === '..' || rel.startsWith(`..${sep}`);
}

function pushGit(findings: Finding[], seen: Set<string>, file: string, spec: string): void {
  if (!npmFlag('NPM_GITDEP')) {return;}
  push(findings, seen, npmFinding(
    GITDEP,
    'high',
    file,
    spec,
    'Git dependency',
    `${spec} is a git dependency. The URL is not cloned.`,
    'Depend on a registry release. Do not clone this URL during the scan.',
  ));
}

function isGit(spec: string): boolean {
  return GIT_PREFIXES.some((prefix) => spec.startsWith(prefix));
}

function nameFromKey(key: string): string | undefined {
  const idx = key.lastIndexOf('node_modules/');
  if (idx === -1) {return undefined;}
  const name = key.slice(idx + 'node_modules/'.length);
  return name.length > 0 ? name : undefined;
}

function isEntry(value: unknown): value is LockEntry {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

interface SourceFile {
  file: string;
  text: string;
}

async function readSources(input: NpmDepthInput): Promise<SourceFile[]> {
  const out: SourceFile[] = [];
  for (const file of input.files) {
    const rel = file.replace(/\\/g, '/');
    if (!SOURCE.test(rel) || rel.includes('node_modules/')) {continue;}
    try {
      const text = await readFile(join(input.cwd, rel), 'utf8');
      if (text.length > 1_000_000) {continue;}
      out.push({ file: rel, text });
    } catch {
      continue;
    }
  }
  return out;
}

interface ImportSite {
  name: string;
  line: number;
  guarded: boolean;
}

function importSites(source: string): ImportSite[] {
  const sites: ImportSite[] = [];
  const patterns = [
    /require\(\s*['"]([^'"]+)['"]\s*\)/g,
    /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /import\s+[^'";]*?\sfrom\s+['"]([^'"]+)['"]/g,
    /import\s+['"]([^'"]+)['"]/g,
  ];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(source)) !== null) {
      const spec = match[1];
      const index = match.index;
      if (spec === undefined || index === undefined) {continue;}
      const name = packageName(spec);
      if (name === undefined) {continue;}
      sites.push({
        name,
        line: source.slice(0, index).split('\n').length,
        guarded: insideTryCatch(source, index),
      });
    }
  }
  return sites;
}

function packageName(spec: string): string | undefined {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) {return undefined;}
  if (BUILTINS.has(spec)) {return undefined;}
  if (spec.startsWith('@')) {
    const parts = spec.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : undefined;
  }
  const name = spec.split('/')[0];
  if (name === undefined || name.length === 0 || BUILTINS.has(name)) {return undefined;}
  return name;
}

function insideTryCatch(source: string, offset: number): boolean {
  const tryDepths: number[] = [];
  let depth = 0;
  let awaitBrace = false;
  let justClosedTry = false;
  let i = 0;
  while (i < offset && i < source.length) {
    const skipped = skipTrivia(source, i);
    if (skipped > i) {
      if (skipped >= offset) {break;}
      i = skipped;
      continue;
    }
    if (isWord(source, i, 'try')) {
      awaitBrace = true;
      justClosedTry = false;
      i += 3;
      continue;
    }
    if (justClosedTry && (isWord(source, i, 'catch') || isWord(source, i, 'finally'))) {
      awaitBrace = true;
      justClosedTry = false;
      i += isWord(source, i, 'catch') ? 5 : 7;
      continue;
    }
    const ch = source[i] ?? '';
    if (ch === '{') {
      if (awaitBrace) {
        tryDepths.push(depth);
        awaitBrace = false;
      }
      depth += 1;
      i += 1;
      continue;
    }
    if (ch === '}') {
      depth -= 1;
      const top = tryDepths[tryDepths.length - 1];
      if (top === depth) {
        tryDepths.pop();
        justClosedTry = true;
      } else {
        justClosedTry = false;
      }
      i += 1;
      continue;
    }
    if (justClosedTry && !/\s/.test(ch)) {justClosedTry = false;}
    i += 1;
  }
  return tryDepths.length > 0;
}

function isWord(source: string, index: number, word: string): boolean {
  if (!source.startsWith(word, index)) {return false;}
  const before = index === 0 ? '' : source[index - 1] ?? '';
  const after = source[index + word.length] ?? '';
  return !/[A-Za-z0-9_$]/.test(before) && !/[A-Za-z0-9_$]/.test(after);
}

function skipTrivia(source: string, index: number): number {
  if (source.startsWith('//', index)) {
    const nl = source.indexOf('\n', index);
    return nl === -1 ? source.length : nl + 1;
  }
  if (source.startsWith('/*', index)) {
    const end = source.indexOf('*/', index + 2);
    return end === -1 ? source.length : end + 2;
  }
  const quote = source[index];
  if (quote !== "'" && quote !== '"' && quote !== '`') {return index;}
  let i = index + 1;
  while (i < source.length) {
    if (source[i] === '\\') {
      i += 2;
      continue;
    }
    if (quote === '`' && source[i] === '$' && source[i + 1] === '{') {
      i += 2;
      let depth = 1;
      while (i < source.length && depth > 0) {
        if (source[i] === '{') {depth += 1;}
        else if (source[i] === '}') {depth -= 1;}
        i += 1;
      }
      continue;
    }
    if (source[i] === quote) {return i + 1;}
    i += 1;
  }
  return source.length;
}
