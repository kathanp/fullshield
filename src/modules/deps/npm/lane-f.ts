import { readdir, readFile } from 'node:fs/promises';
import { relative, resolve, join } from 'node:path';

import type { Confidence, Finding, Severity } from '../../../core/finding.js';
import { registryCachePath } from '../../../provenance/index.js';
import { POPULAR_PACKAGES } from '../popular.js';
import { currentFacts } from './facts.js';
import { npmFinding, npmFlag, npmRow, type NpmDepthInput, type NpmDepthRow } from './types.js';

/**
 * Phases 208–225 emit findings. Phases 226 and 227 do not add a rule id:
 * 226 is the popular-name file, 227 keeps distance-2 names silent.
 */

const SCOPE_TYPO = 'DEPS-SCOPE-TYPO-001';
const HOMOGLYPH = 'DEPS-HOMOGLYPH-001';
const BIDI = 'DEPS-BIDI-001';
const MIXEDSCRIPT = 'DEPS-MIXEDSCRIPT-001';
const SEPARATOR = 'DEPS-SEPARATOR-001';
const REPEAT = 'DEPS-REPEAT-001';
const SUFFIX = 'DEPS-SUFFIX-001';
const SCOPE_NEW = 'DEPS-SCOPE-NEW-001';
const SCOPE_SYNTAX = 'DEPS-SCOPE-SYNTAX-001';
const TYPES = 'DEPS-TYPES-001';
const DEPRECATED_REPLACE = 'DEPS-DEPRECATED-REPLACE-001';
const TYPO_TRANSITIVE = 'DEPS-TYPO-TRANSITIVE-001';
const NAME_LENGTH = 'DEPS-NAME-LENGTH-001';
const NAME_CASE = 'DEPS-NAME-CASE-001';
const NAME_ENCODED = 'DEPS-NAME-ENCODED-001';
const ALIAS_SQUAT = 'DEPS-ALIAS-SQUAT-001';
const SELFNAME = 'DEPS-SELFNAME-001';
const WORKSPACE_NAME = 'DEPS-WORKSPACE-NAME-001';

const FLAGS = [
  'NPM_SCOPE_TYPO',
  'NPM_HOMOGLYPH',
  'NPM_BIDI',
  'NPM_MIXEDSCRIPT',
  'NPM_SEPARATOR',
  'NPM_REPEAT',
  'NPM_SUFFIX',
  'NPM_SCOPE_NEW',
  'NPM_SCOPE_SYNTAX',
  'NPM_TYPES',
  'NPM_DEPRECATED_REPLACE',
  'NPM_TYPO_TRANSITIVE',
  'NPM_NAME_LENGTH',
  'NPM_NAME_CASE',
  'NPM_NAME_ENCODED',
  'NPM_ALIAS_SQUAT',
  'NPM_SELFNAME',
  'NPM_WORKSPACE_NAME',
  'NPM_POPULAR_LIST',
  'NPM_DISTANCE2',
] as const;

const MANIFEST = 'package.json';
const LOCK = 'package-lock.json';
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
const NAME_LIMIT = 214;
const SUFFIXES = ['-js', '-node', '-npm', '-lib'] as const;
const DIRECT_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

/** Scoped names must match the phase 216 grammar exactly. */
const SCOPED_OK = /^@[a-z0-9-~][a-z0-9-._~]*\/[a-z0-9-~][a-z0-9-._~]*$/;
const PACKAGE_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

/**
 * Cyrillic and Greek lookalikes for a, e, o, p, c, x, y. Literal, not fetched.
 * а/α e/ε о/ο р/ρ с/ϲ х/χ у/γ
 */
const CONFUSABLES: ReadonlyMap<string, string> = new Map([
  ['\u0430', 'a'],
  ['\u03b1', 'a'],
  ['\u0435', 'e'],
  ['\u03b5', 'e'],
  ['\u043e', 'o'],
  ['\u03bf', 'o'],
  ['\u0440', 'p'],
  ['\u03c1', 'p'],
  ['\u0441', 'c'],
  ['\u03f2', 'c'],
  ['\u0445', 'x'],
  ['\u03c7', 'x'],
  ['\u0443', 'y'],
  ['\u03b3', 'y'],
]);

const popularSet = new Set(POPULAR_PACKAGES);
const basenames = new Set<string>();
const scopes = new Set<string>();
const basenamesByScope = new Map<string, Set<string>>();
const bySeparator = new Map<string, string[]>();

for (const name of POPULAR_PACKAGES) {
  const normalized = normalizeSeparators(name);
  const group = bySeparator.get(normalized);
  if (group === undefined) {bySeparator.set(normalized, [name]);}
  else {group.push(name);}
  const scoped = splitScoped(name);
  if (scoped === undefined) {
    basenames.add(name);
    continue;
  }
  scopes.add(scoped.scope);
  basenames.add(scoped.base);
  const bases = basenamesByScope.get(scoped.scope) ?? new Set<string>();
  bases.add(scoped.base);
  basenamesByScope.set(scoped.scope, bases);
}

export const laneRows: readonly NpmDepthRow[] = [
  npmRow(SCOPE_TYPO, 'CWE-494'),
  npmRow(HOMOGLYPH, 'CWE-1007'),
  npmRow(BIDI, 'CWE-1007'),
  npmRow(MIXEDSCRIPT, 'CWE-1007'),
  npmRow(SEPARATOR, 'CWE-494'),
  npmRow(REPEAT, 'CWE-494'),
  npmRow(SUFFIX, 'CWE-494'),
  npmRow(SCOPE_NEW, 'CWE-1104'),
  npmRow(SCOPE_SYNTAX, 'CWE-20'),
  npmRow(TYPES, 'CWE-1104'),
  npmRow(DEPRECATED_REPLACE, 'CWE-1104'),
  npmRow(TYPO_TRANSITIVE, 'CWE-494'),
  npmRow(NAME_LENGTH, 'CWE-1284'),
  npmRow(NAME_CASE, 'CWE-178'),
  npmRow(NAME_ENCODED, 'CWE-20'),
  npmRow(ALIAS_SQUAT, 'CWE-494'),
  npmRow(SELFNAME, 'CWE-694'),
  npmRow(WORKSPACE_NAME, 'CWE-494'),
];

interface Hit {
  flag: string;
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  check: string;
  title: string;
  message: string;
  remediation: string;
}

interface DirectDep {
  name: string;
  spec: string;
}

interface LockPkg {
  names: readonly string[];
  subject: string;
  resolved?: string;
  deprecated?: string;
}

function laneEnabled(): boolean {
  return FLAGS.some((flag) => npmFlag(flag));
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {return undefined;}
  return value as Record<string, unknown>;
}

function parseJson(text: string | undefined): Record<string, unknown> | undefined {
  if (text === undefined) {return undefined;}
  try {
    return asRecord(JSON.parse(text) as unknown);
  } catch {
    return undefined;
  }
}

function splitScoped(name: string): { scope: string; base: string } | undefined {
  if (!name.startsWith('@')) {return undefined;}
  const slash = name.indexOf('/');
  if (slash <= 1 || name.indexOf('/', slash + 1) !== -1) {return undefined;}
  const scope = name.slice(1, slash);
  const base = name.slice(slash + 1);
  if (scope.length === 0 || base.length === 0) {return undefined;}
  return { scope, base };
}

function normalizeSeparators(name: string): string {
  return name.replaceAll('.', '-').replaceAll('_', '-');
}

function levenshteinAtMost1(a: string, b: string): number | undefined {
  if (a === b) {return 0;}
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) {return undefined;}
  if (la === lb) {
    let diffs = 0;
    for (let i = 0; i < la; i += 1) {
      if (a[i] !== b[i]) {
        diffs += 1;
        if (diffs > 1) {return undefined;}
      }
    }
    return diffs;
  }
  const shorter = la < lb ? a : b;
  const longer = la < lb ? b : a;
  let si = 0;
  let skipped = false;
  for (let li = 0; li < longer.length; li += 1) {
    if (shorter[si] === longer[li]) {
      si += 1;
      continue;
    }
    if (skipped) {return undefined;}
    skipped = true;
  }
  return 1;
}

function withinOneEdit(name: string): boolean {
  for (const popular of POPULAR_PACKAGES) {
    if (levenshteinAtMost1(name, popular) === 1) {return true;}
  }
  return false;
}

function isAscii(name: string): boolean {
  for (let i = 0; i < name.length; i += 1) {
    if (name.charCodeAt(i) > 0x7f) {return false;}
  }
  return true;
}

function hasBidi(name: string): boolean {
  for (const char of name) {
    const code = char.codePointAt(0);
    if (code === undefined) {continue;}
    if ((code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069) || (code >= 0x200b && code <= 0x200f)) {
      return true;
    }
  }
  return false;
}

function mixedScript(name: string): boolean {
  let latin = false;
  let other = false;
  for (const char of name) {
    if (/\p{Script=Latin}/u.test(char)) {latin = true;}
    else if (/\p{Script=Cyrillic}/u.test(char) || /\p{Script=Greek}/u.test(char)) {other = true;}
    if (latin && other) {return true;}
  }
  return false;
}

function homoglyphTarget(name: string): string | undefined {
  if (isAscii(name)) {return undefined;}
  const nfkc = name.normalize('NFKC');
  if (popularSet.has(nfkc)) {return nfkc;}
  let mapped = '';
  let saw = false;
  for (const char of name) {
    const next = CONFUSABLES.get(char);
    if (next === undefined) {mapped += char;}
    else {
      saw = true;
      mapped += next;
    }
  }
  if (!saw || !popularSet.has(mapped)) {return undefined;}
  return mapped;
}

function scopeTypo(name: string): { scope: string; popular: string; base: string } | undefined {
  const parts = splitScoped(name);
  if (parts === undefined || scopes.has(parts.scope)) {return undefined;}
  let popular: string | undefined;
  for (const candidate of scopes) {
    if (levenshteinAtMost1(parts.scope, candidate) !== 1) {continue;}
    if (!basenamesByScope.get(candidate)?.has(parts.base)) {continue;}
    if (popular === undefined || candidate < popular) {popular = candidate;}
  }
  if (popular === undefined) {return undefined;}
  return { scope: parts.scope, popular, base: parts.base };
}

/** A distance-1 separator twin is left to the direct edit check and is not emitted here. */
function separatorTarget(name: string): string | undefined {
  const matches = bySeparator.get(normalizeSeparators(name));
  if (matches === undefined) {return undefined;}
  let best: string | undefined;
  for (const popular of matches) {
    if (popular === name) {return undefined;}
    const distance = levenshteinAtMost1(name, popular);
    if (distance === 0 || distance === 1) {return undefined;}
    if (best === undefined || popular < best) {best = popular;}
  }
  return best;
}

function repeatBase(name: string): string | undefined {
  let base: string | undefined;
  const parts = splitScoped(name);
  if (name.startsWith('@')) {
    if (parts === undefined || parts.scope !== parts.base) {return undefined;}
    base = parts.scope;
  } else {
    base = /^(.+)-\1$/.exec(name)?.[1];
  }
  if (base === undefined || !basenames.has(base) || withinOneEdit(name)) {return undefined;}
  return base;
}

function suffixBase(name: string): string | undefined {
  if (popularSet.has(name)) {return undefined;}
  for (const suffix of SUFFIXES) {
    if (!name.endsWith(suffix)) {continue;}
    const base = name.slice(0, -suffix.length);
    if (base.length > 0 && popularSet.has(base)) {return base;}
  }
  return undefined;
}

function lookalikeHits(name: string): Hit[] {
  const hits: Hit[] = [];
  const scope = scopeTypo(name);
  if (scope !== undefined) {
    hits.push({
      flag: 'NPM_SCOPE_TYPO',
      ruleId: SCOPE_TYPO,
      severity: 'medium',
      confidence: 'medium',
      check: 'scope typo',
      title: `Scope is one edit from @${scope.popular}`,
      message: `Direct dependency "${name}" has scope "${scope.scope}", one edit from popular scope "${scope.popular}", and basename "${scope.base}" matches a package in that scope.`,
      remediation: `Depend on @${scope.popular}/${scope.base} if that is the package you meant.`,
    });
  }
  const homoglyph = homoglyphTarget(name);
  if (homoglyph !== undefined) {
    hits.push({
      flag: 'NPM_HOMOGLYPH',
      ruleId: HOMOGLYPH,
      severity: 'high',
      confidence: 'high',
      check: 'homoglyph',
      title: `Dependency name looks like ${homoglyph}`,
      message: `Dependency "${name}" is not ASCII and matches popular package "${homoglyph}" after normalization.`,
      remediation: 'Confirm the package name character by character before installing it.',
    });
  }
  if (hasBidi(name)) {
    hits.push({
      flag: 'NPM_BIDI',
      ruleId: BIDI,
      severity: 'critical',
      confidence: 'high',
      check: 'bidi',
      title: 'Dependency name contains a hidden or bidi character',
      message: `Dependency "${name}" contains a character in U+202A–U+202E, U+2066–U+2069, or U+200B–U+200F.`,
      remediation: 'Remove the dependency and use an ASCII package name.',
    });
  }
  if (homoglyph === undefined && mixedScript(name)) {
    hits.push({
      flag: 'NPM_MIXEDSCRIPT',
      ruleId: MIXEDSCRIPT,
      severity: 'high',
      confidence: 'high',
      check: 'mixed script',
      title: 'Dependency name mixes Latin and Cyrillic or Greek',
      message: `Dependency "${name}" contains both a Latin letter and a Cyrillic or Greek letter.`,
      remediation: 'Use a package name written in one script.',
    });
  }
  const separator = separatorTarget(name);
  if (separator !== undefined) {
    hits.push({
      flag: 'NPM_SEPARATOR',
      ruleId: SEPARATOR,
      severity: 'medium',
      confidence: 'medium',
      check: 'separator',
      title: `Dependency name swaps separators in ${separator}`,
      message: `Direct dependency "${name}" matches popular package "${separator}" when ".", "-", and "_" are treated as the same character.`,
      remediation: `Confirm you intended "${name}" rather than "${separator}".`,
    });
  }
  return hits;
}

function checkLabel(checks: readonly string[]): string {
  if (checks.length === 1) {return `the ${checks[0] ?? ''} check`;}
  if (checks.length === 2) {return `the ${checks[0] ?? ''} and ${checks[1] ?? ''} checks`;}
  const last = checks[checks.length - 1] ?? '';
  return `the ${checks.slice(0, -1).join(', ')}, and ${last} checks`;
}

function directDeps(manifest: Record<string, unknown>): DirectDep[] {
  const out: DirectDep[] = [];
  for (const field of DIRECT_FIELDS) {
    const block = asRecord(manifest[field]);
    if (block === undefined) {continue;}
    for (const [name, spec] of Object.entries(block)) {
      out.push({ name, spec: typeof spec === 'string' ? spec : '' });
    }
  }
  return out;
}

function nameFromPackagesKey(key: string): string | undefined {
  if (key === '') {return undefined;}
  const idx = key.lastIndexOf('node_modules/');
  if (idx === -1) {return undefined;}
  const name = key.slice(idx + 'node_modules/'.length);
  return name.length > 0 ? name : undefined;
}

function collectRootAliases(entry: Record<string, unknown>, aliasSpecs: DirectDep[]): void {
  for (const field of DIRECT_FIELDS) {
    const block = asRecord(entry[field]);
    if (block === undefined) {continue;}
    for (const [name, spec] of Object.entries(block)) {
      if (typeof spec === 'string') {aliasSpecs.push({ name, spec });}
    }
  }
}

function lockPkg(keyName: string, entry: Record<string, unknown>): LockPkg {
  const entryName = typeof entry.name === 'string' && entry.name.length > 0 ? entry.name : undefined;
  const names = entryName !== undefined && entryName !== keyName ? [keyName, entryName] : [keyName];
  return {
    names,
    subject: entryName ?? keyName,
    resolved: typeof entry.resolved === 'string' ? entry.resolved : undefined,
    deprecated: typeof entry.deprecated === 'string' ? entry.deprecated : undefined,
  };
}

function pushLockRow(
  key: string,
  value: unknown,
  packages: LockPkg[],
  aliasSpecs: DirectDep[],
): void {
  const entry = asRecord(value);
  if (entry === undefined) {return;}
  if (key === '') {
    collectRootAliases(entry, aliasSpecs);
    return;
  }
  const keyName = nameFromPackagesKey(key);
  if (keyName === undefined) {return;}
  packages.push(lockPkg(keyName, entry));
}

function lockPackages(text: string | undefined): { packages: LockPkg[]; aliasSpecs: DirectDep[] } {
  const doc = parseJson(text);
  const table = asRecord(doc?.packages);
  if (table === undefined) {return { packages: [], aliasSpecs: [] };}
  const packages: LockPkg[] = [];
  const aliasSpecs: DirectDep[] = [];
  for (const [key, value] of Object.entries(table)) {
    pushLockRow(key, value, packages, aliasSpecs);
  }
  return { packages, aliasSpecs };
}

function aliasTarget(spec: string): string | undefined {
  if (!spec.startsWith('npm:')) {return undefined;}
  const body = spec.slice(4);
  if (body.length === 0) {return undefined;}
  if (body.startsWith('@')) {
    const slash = body.indexOf('/');
    if (slash === -1) {return undefined;}
    const at = body.indexOf('@', slash + 1);
    const name = at === -1 ? body : body.slice(0, at);
    return name.length > 0 ? name : undefined;
  }
  const at = body.indexOf('@');
  const name = at === -1 ? body : body.slice(0, at);
  return name.length > 0 ? name : undefined;
}

function replacementName(text: string): string | undefined {
  const match = /(?:replaced by|\buse)\s+[`'"]?(@[a-z0-9-~][a-z0-9-._~]*\/[a-z0-9-~][a-z0-9-._~]*|[a-z0-9-~][a-z0-9-._~]*)/i.exec(text);
  const raw = match?.[1];
  if (raw === undefined) {return undefined;}
  const name = raw.endsWith('.') ? raw.slice(0, -1) : raw;
  if (!PACKAGE_NAME.test(name)) {return undefined;}
  return name;
}

function asciiLower(name: string): string {
  return name.replace(/[A-Z]/g, (char) => char.toLowerCase());
}

function quoteList(names: readonly string[]): string {
  const quoted = names.map((name) => `"${name}"`);
  if (quoted.length === 2) {return `${quoted[0] ?? ''} and ${quoted[1] ?? ''}`;}
  const last = quoted[quoted.length - 1] ?? '';
  return `${quoted.slice(0, -1).join(', ')}, and ${last}`;
}

function workspacePatterns(manifest: Record<string, unknown>): string[] {
  const field = manifest.workspaces;
  if (Array.isArray(field)) {return field.filter((item): item is string => typeof item === 'string');}
  const record = asRecord(field);
  if (record !== undefined && Array.isArray(record.packages)) {
    return record.packages.filter((item): item is string => typeof item === 'string');
  }
  return [];
}

function insideCwd(cwd: string, rel: string): boolean {
  const diff = relative(cwd, resolve(cwd, rel));
  return diff === '' || (!diff.startsWith('..') && !diff.includes('..'));
}

async function expandWorkspace(cwd: string, pattern: string): Promise<string[]> {
  const normalized = pattern.replaceAll('\\', '/').replace(/^\.\//, '');
  if (normalized === '' || normalized.split('/').includes('..') || !insideCwd(cwd, normalized === '' ? '.' : normalized.split('*')[0] || '.')) {
    return [];
  }
  if (!normalized.includes('*')) {return insideCwd(cwd, normalized) ? [normalized] : [];}
  const slash = normalized.indexOf('/*');
  if (slash < 0) {return [];}
  const parent = normalized.slice(0, slash);
  if (parent.split('/').includes('..') || !insideCwd(cwd, parent === '' ? '.' : parent)) {return [];}
  try {
    const entries = await readdir(join(cwd, parent), { withFileTypes: true });
    return entries
      .filter((entry) => entry.isDirectory())
      .map((entry) => (parent === '' ? entry.name : `${parent}/${entry.name}`))
      .filter((rel) => insideCwd(cwd, rel))
      .sort();
  } catch {
    return [];
  }
}

async function workspacePackageNames(cwd: string, manifest: Record<string, unknown>): Promise<string[]> {
  const names: string[] = [];
  for (const pattern of workspacePatterns(manifest)) {
    for (const dir of await expandWorkspace(cwd, pattern)) {
      try {
        const raw = JSON.parse(await readFile(join(cwd, dir, 'package.json'), 'utf8')) as unknown;
        const name = asRecord(raw)?.name;
        if (typeof name === 'string' && name.length > 0) {names.push(name);}
      } catch {
        // unreadable workspace manifest is not a name finding
      }
    }
  }
  return names;
}

function packumentBody(raw: unknown): Record<string, unknown> | undefined {
  const doc = asRecord(raw);
  if (doc === undefined) {return undefined;}
  const nested = asRecord(doc.packument);
  if (nested !== undefined && (asRecord(nested.time) !== undefined || asRecord(nested.versions) !== undefined)) {
    return nested;
  }
  if (asRecord(doc.time) !== undefined || asRecord(doc.versions) !== undefined) {return doc;}
  return undefined;
}

async function readPackument(cacheDir: string, name: string): Promise<Record<string, unknown> | undefined> {
  const held = currentFacts()?.packuments.get(name);
  if (held !== undefined) {return packumentBody(held);}
  try {
    return packumentBody(JSON.parse(await readFile(registryCachePath(cacheDir, name), 'utf8')) as unknown);
  } catch {
    return undefined;
  }
}

function earliestVersionTime(body: Record<string, unknown>): number | undefined {
  const time = asRecord(body.time);
  if (time === undefined) {return undefined;}
  let earliest: number | undefined;
  for (const [key, value] of Object.entries(time)) {
    if (key === 'created' || key === 'modified' || typeof value !== 'string') {continue;}
    const stamp = Date.parse(value);
    if (!Number.isFinite(stamp)) {continue;}
    if (earliest === undefined || stamp < earliest) {earliest = stamp;}
  }
  return earliest;
}

function hasTypesField(record: Record<string, unknown>): boolean {
  return (typeof record.types === 'string' && record.types.length > 0)
    || (typeof record.typings === 'string' && record.typings.length > 0);
}

function hasTypes(body: Record<string, unknown>): boolean {
  if (hasTypesField(body)) {return true;}
  const versions = asRecord(body.versions);
  if (versions === undefined) {return false;}
  for (const entry of Object.values(versions)) {
    const row = asRecord(entry);
    if (row !== undefined && hasTypesField(row)) {return true;}
  }
  return false;
}

function isRegistryResolved(resolved: string): boolean {
  if (resolved.startsWith('link:') || resolved.startsWith('file:')) {return false;}
  try {
    return new URL(resolved).host === 'registry.npmjs.org';
  } catch {
    return false;
  }
}

interface LaneAdd {
  ruleId: string;
  severity: Severity;
  file: string;
  snippet: string;
  title: string;
  message: string;
  remediation: string;
  confidence?: Confidence;
}

interface LaneState {
  input: NpmDepthInput;
  manifest: Record<string, unknown>;
  direct: DirectDep[];
  directSet: Set<string>;
  lock: { packages: LockPkg[]; aliasSpecs: DirectDep[] };
  lockedNames: string[];
  findings: Finding[];
  seen: Set<string>;
}

function pushLane(findings: Finding[], seen: Set<string>, row: LaneAdd): void {
  const key = `${row.ruleId}\0${row.snippet}`;
  if (seen.has(key)) {return;}
  seen.add(key);
  findings.push(npmFinding({
    ruleId: row.ruleId,
    severity: row.severity,
    file: row.file,
    snippet: row.snippet,
    title: row.title,
    message: row.message,
    remediation: row.remediation,
    confidence: row.confidence,
  }));
}

function laneState(input: NpmDepthInput): LaneState {
  const manifest = parseJson(input.manifestRaw) ?? {};
  const direct = directDeps(manifest);
  const lock = lockPackages(input.lockTexts[LOCK]);
  return {
    input,
    manifest,
    direct,
    directSet: new Set(direct.map((dep) => dep.name)),
    lock,
    lockedNames: [...new Set(lock.packages.flatMap((pkg) => pkg.names))],
    findings: [],
    seen: new Set(),
  };
}

function locatedNames(state: LaneState): Map<string, string> {
  const located = new Map<string, string>();
  for (const dep of state.direct) {located.set(dep.name, MANIFEST);}
  for (const name of state.lockedNames) {
    if (!located.has(name)) {located.set(name, LOCK);}
  }
  return located;
}

function addLookalike(state: LaneState, name: string, file: string): void {
  const directName = state.directSet.has(name);
  const hits = lookalikeHits(name);
  if (!directName && npmFlag('NPM_TYPO_TRANSITIVE') && hits.length > 0) {
    const checks = hits.map((hit) => hit.check);
    pushLane(state.findings, state.seen, {
      ruleId: TYPO_TRANSITIVE,
      severity: 'info',
      file: LOCK,
      snippet: name,
      title: `Transitive name check: ${name}`,
      message: `Transitive dependency "${name}" matches ${checkLabel(checks)}.`,
      remediation: 'Confirm the transitive package name. This row is informational.',
      confidence: 'medium',
    });
    return;
  }
  for (const hit of hits) {
    if (!directName && (hit.check === 'scope typo' || hit.check === 'separator')) {continue;}
    if (!npmFlag(hit.flag)) {continue;}
    pushLane(state.findings, state.seen, {
      ruleId: hit.ruleId,
      severity: hit.severity,
      file,
      snippet: name,
      title: hit.title,
      message: hit.message,
      remediation: hit.remediation,
      confidence: hit.confidence,
    });
  }
}

function addScopeSyntax(state: LaneState, name: string, file: string): void {
  if (!npmFlag('NPM_SCOPE_SYNTAX') || !name.startsWith('@') || SCOPED_OK.test(name)) {return;}
  pushLane(state.findings, state.seen, {
    ruleId: SCOPE_SYNTAX,
    severity: 'high',
    file,
    snippet: name,
    title: 'Dependency name is not a valid scoped package name',
    message: `Dependency "${name}" starts with "@" and is not @scope/name.`,
    remediation: 'Use a scoped name of the form @scope/name, with a single slash.',
  });
}

function nameLengthMessage(name: string): string {
  if (name.length === 0) {return 'A dependency name is empty. npm package names must be 1 to 214 characters.';}
  return `Dependency "${name}" is ${String(name.length)} characters. npm's documented limit is 214.`;
}

function addNameLength(state: LaneState, name: string, file: string): void {
  if (!npmFlag('NPM_NAME_LENGTH') || (name.length !== 0 && name.length <= NAME_LIMIT)) {return;}
  const empty = name.length === 0;
  pushLane(state.findings, state.seen, {
    ruleId: NAME_LENGTH,
    severity: 'high',
    file,
    snippet: empty ? '(empty)' : name,
    title: 'Dependency name length is outside npm\'s limit',
    message: nameLengthMessage(name),
    remediation: 'Use a package name within npm\'s 214 character limit.',
  });
}

function addNameEncoded(state: LaneState, name: string, file: string): void {
  if (!npmFlag('NPM_NAME_ENCODED') || !name.includes('%')) {return;}
  pushLane(state.findings, state.seen, {
    ruleId: NAME_ENCODED,
    severity: 'high',
    file,
    snippet: name,
    title: 'Dependency name contains percent-encoding',
    message: `Dependency "${name}" contains "%".`,
    remediation: 'Depend on the package by its registry name, without percent-encoding.',
  });
}

function addLocatedFindings(state: LaneState, located: Map<string, string>): void {
  for (const [name, file] of located) {
    addLookalike(state, name, file);
    addScopeSyntax(state, name, file);
    addNameLength(state, name, file);
    addNameEncoded(state, name, file);
  }
}

function addRepeatFindings(state: LaneState): void {
  if (!npmFlag('NPM_REPEAT')) {return;}
  for (const dep of state.direct) {
    const base = repeatBase(dep.name);
    if (base === undefined) {continue;}
    pushLane(state.findings, state.seen, {
      ruleId: REPEAT,
      severity: 'medium',
      file: MANIFEST,
      snippet: dep.name,
      title: `Dependency name repeats ${base}`,
      message: `Direct dependency "${dep.name}" repeats the popular package basename "${base}".`,
      remediation: `Confirm you intended "${dep.name}".`,
      confidence: 'medium',
    });
  }
}

function addSuffixFindings(state: LaneState): void {
  if (!npmFlag('NPM_SUFFIX')) {return;}
  for (const dep of state.direct) {
    const base = suffixBase(dep.name);
    if (base === undefined) {continue;}
    pushLane(state.findings, state.seen, {
      ruleId: SUFFIX,
      severity: 'low',
      file: MANIFEST,
      snippet: dep.name,
      title: `Dependency name adds a suffix to ${base}`,
      message: `Confirm you intended to depend on "${dep.name}". It is the popular package "${base}" plus a common suffix.`,
      remediation: 'Keep the dependency only if that name is the package you meant.',
      confidence: 'low',
    });
  }
}

function addCaseFindings(state: LaneState): void {
  if (!npmFlag('NPM_NAME_CASE')) {return;}
  const groups = new Map<string, Set<string>>();
  for (const name of state.lockedNames) {
    const key = asciiLower(name);
    const group = groups.get(key) ?? new Set<string>();
    group.add(name);
    groups.set(key, group);
  }
  for (const group of groups.values()) {
    if (group.size < 2) {continue;}
    const names = [...group].sort();
    pushLane(state.findings, state.seen, {
      ruleId: NAME_CASE,
      severity: 'high',
      file: LOCK,
      snippet: names.join('|'),
      title: 'Locked package names differ only by case',
      message: `Locked names ${quoteList(names)} differ only by ASCII case.`,
      remediation: 'Keep one spelling. npm package names are lowercase, and case-only variants collide on some file systems.',
    });
  }
}

function addAliasFindings(state: LaneState): void {
  if (!npmFlag('NPM_ALIAS_SQUAT')) {return;}
  for (const dep of [...state.direct, ...state.lock.aliasSpecs]) {
    const target = aliasTarget(dep.spec);
    if (target === undefined || target === dep.name || !popularSet.has(dep.name)) {continue;}
    pushLane(state.findings, state.seen, {
      ruleId: ALIAS_SQUAT,
      severity: 'high',
      file: MANIFEST,
      snippet: `${dep.name} => ${target}`,
      title: `Alias requests ${dep.name} and installs ${target}`,
      message: `The alias requests popular package "${dep.name}" and installs "${target}".`,
      remediation: `Point the alias at ${dep.name} if that is the package you meant, or rename the request so it does not look like ${dep.name}.`,
    });
  }
}

function addSelfNameFindings(state: LaneState): void {
  const project = state.manifest.name;
  if (!npmFlag('NPM_SELFNAME') || typeof project !== 'string') {return;}
  for (const dep of state.direct) {
    if (dep.name !== project) {continue;}
    if (dep.spec.startsWith('file:') || dep.spec.startsWith('workspace:')) {continue;}
    pushLane(state.findings, state.seen, {
      ruleId: SELFNAME,
      severity: 'medium',
      file: MANIFEST,
      snippet: dep.name,
      title: 'Dependency name matches the project name',
      message: `Dependency "${dep.name}" matches this project's name and is not a file: or workspace: path.`,
      remediation: 'Use a workspace: or file: spec for the local package, or rename the dependency.',
      confidence: 'high',
    });
  }
}

function addDeprecatedFindings(state: LaneState): void {
  if (!npmFlag('NPM_DEPRECATED_REPLACE')) {return;}
  for (const pkg of state.lock.packages) {
    if (pkg.deprecated === undefined) {continue;}
    const replacement = replacementName(pkg.deprecated);
    if (replacement === undefined || state.directSet.has(replacement)) {continue;}
    pushLane(state.findings, state.seen, {
      ruleId: DEPRECATED_REPLACE,
      severity: 'info',
      file: LOCK,
      snippet: `${pkg.subject} -> ${replacement}`,
      title: `Deprecated package names ${replacement}`,
      message: `"${pkg.subject}" is deprecated and names "${replacement}", which is not a direct dependency.`,
      remediation: `Read the deprecation notice and decide whether to depend on ${replacement}.`,
    });
  }
}

async function addScopeNewFindings(state: LaneState): Promise<void> {
  if (!npmFlag('NPM_SCOPE_NEW')) {return;}
  const project = state.manifest.name;
  const rootScope = typeof project === 'string' ? splitScoped(project)?.scope : undefined;
  for (const dep of state.direct) {
    const scope = splitScoped(dep.name)?.scope;
    if (scope === undefined || scope === rootScope) {continue;}
    const body = await readPackument(state.input.cacheDir, dep.name);
    const earliest = body === undefined ? undefined : earliestVersionTime(body);
    if (earliest === undefined || Date.now() - earliest >= WEEK_MS) {continue;}
    pushLane(state.findings, state.seen, {
      ruleId: SCOPE_NEW,
      severity: 'medium',
      file: MANIFEST,
      snippet: dep.name,
      title: `Scoped dependency ${dep.name} was first published recently`,
      message: `Direct dependency "${dep.name}" was first published within the last 7 days, and its scope is not this project's scope.`,
      remediation: 'Confirm the scope is one you trust before installing a newly published package.',
      confidence: 'medium',
    });
  }
}

async function addTypesFindings(state: LaneState): Promise<void> {
  if (!npmFlag('NPM_TYPES')) {return;}
  for (const dep of state.direct) {
    if (dep.name.startsWith('@') || dep.name.length === 0 || !state.directSet.has(`@types/${dep.name}`)) {continue;}
    const body = await readPackument(state.input.cacheDir, dep.name);
    if (body === undefined || !hasTypes(body)) {continue;}
    pushLane(state.findings, state.seen, {
      ruleId: TYPES,
      severity: 'info',
      file: MANIFEST,
      snippet: dep.name,
      title: `Redundant @types/${dep.name}`,
      message: `"${dep.name}" already publishes types, and the project also depends on "@types/${dep.name}".`,
      remediation: `Remove @types/${dep.name} if the package's own types are the ones TypeScript should use.`,
    });
  }
}

function registryWorkspaceNames(state: LaneState, wanted: ReadonlySet<string>): Set<string> {
  const bad = new Set<string>();
  for (const pkg of state.lock.packages) {
    if (pkg.resolved === undefined || !isRegistryResolved(pkg.resolved)) {continue;}
    for (const name of pkg.names) {
      if (wanted.has(name)) {bad.add(name);}
    }
  }
  return bad;
}

async function addWorkspaceFindings(state: LaneState): Promise<void> {
  if (!npmFlag('NPM_WORKSPACE_NAME')) {return;}
  const wanted = new Set(await workspacePackageNames(state.input.cwd, state.manifest));
  for (const name of [...registryWorkspaceNames(state, wanted)].sort()) {
    pushLane(state.findings, state.seen, {
      ruleId: WORKSPACE_NAME,
      severity: 'high',
      file: LOCK,
      snippet: name,
      title: `Workspace package ${name} is resolved from the registry`,
      message: `Workspace package "${name}" is resolved from registry.npmjs.org rather than a link: or file: path.`,
      remediation: 'Link the workspace package with link: or file: so install does not fetch a registry package of the same name.',
    });
  }
}

export async function laneFindings(input: NpmDepthInput): Promise<Finding[]> {
  if (!laneEnabled()) {return [];}
  const state = laneState(input);
  addLocatedFindings(state, locatedNames(state));
  addRepeatFindings(state);
  addSuffixFindings(state);
  addCaseFindings(state);
  addAliasFindings(state);
  addSelfNameFindings(state);
  addDeprecatedFindings(state);
  await addScopeNewFindings(state);
  await addTypesFindings(state);
  await addWorkspaceFindings(state);
  return state.findings;
}
