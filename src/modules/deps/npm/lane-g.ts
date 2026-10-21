import { builtinModules } from 'node:module';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding } from '../../../core/finding.js';
import { lockUsesElectron, packageUsesElectron } from '../../config/electron.js';
import { registryCachePath } from '../../../provenance/index.js';
import { npmFinding, npmFlag, npmRow, type NpmDepthInput, type NpmDepthRow } from './types.js';

const BUILTINS = new Set(builtinModules.flatMap((name) => [name, name.replace(/^node:/, '')]));

/** Today's import-level class. Flag-off helpers return this unchanged. */
export type ImportReach =
  | 'reachable'
  | 'imported-not-called'
  | 'reachable-via-dependency'
  | 'not-imported';

export interface GraphCopy {
  /** Lockfile path, e.g. `node_modules/a/node_modules/b`. */
  path: string;
  name: string;
  /** Parent lockfile paths that require this copy. */
  requiredBy: readonly string[];
  /** Acceptance label only. Classification does not read it. */
  vulnerable?: boolean;
}

export interface ImportedRoot {
  name: string;
  called: boolean;
}

export interface InstanceClass {
  path: string;
  name: string;
  reachability: ImportReach;
}

export interface DynamicSpec {
  name?: string;
  literal: boolean;
  countsAsImport: boolean;
  reachability?: 'reachability-unknown';
  /** Literal specifier the static walker already counted. Not a second import. */
  alreadyCounted: boolean;
}

export interface WorkerHit {
  name?: string;
  literal: boolean;
  countsAsCall: boolean;
  reachability?: 'reachability-unknown';
}

export interface SubpathResult {
  kind: 'symbol' | 'import' | 'not-a-reach';
  target?: string;
}

export interface ReexportHit {
  name?: string;
  countsAsImport: boolean;
  typeOnly: boolean;
}

export interface TypeImportHit {
  name: string;
  countsAsImport: boolean;
  typeOnly: boolean;
}

export interface TryRequireHit {
  name: string;
  line: number;
  imported: true;
  optionalImport?: true;
}

export interface RuntimeDeps {
  manifest?: string;
  lockText?: string;
  /** Package names already depended on. `react-native` is honored only when listed. */
  packages?: readonly string[];
}

interface LockEntry {
  name?: string;
  version?: string;
  dependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
}

interface RawCall {
  name?: string;
  literal: boolean;
  index: number;
}

const OPTIONAL_ID = 'DEPS-GRAPH-OPTIONAL-001';
const PEER_ID = 'DEPS-PEER-MISSING-001';
const ALIAS_ID = 'DEPS-GRAPH-ALIAS-001';
const DUAL_ID = 'DEPS-DUALPACKAGE-001';
const PHANTOM_ID = 'DEPS-PHANTOM-002';

export const laneRows: readonly NpmDepthRow[] = [
  npmRow(OPTIONAL_ID, 'CWE-829'),
  npmRow(PEER_ID, 'CWE-829'),
  npmRow(ALIAS_ID, 'CWE-829'),
  npmRow(DUAL_ID, 'CWE-829'),
  npmRow(PHANTOM_ID, 'CWE-829'),
];

/** Phase 228. Flag off unions copies by name. Flag on keeps each lockfile path. */
export function classifyInstance(
  flag: boolean,
  copies: readonly GraphCopy[],
  roots: readonly ImportedRoot[],
): InstanceClass[] {
  const imported = importedMap(roots);
  return flag ? classifyByPath(copies, imported) : classifyByName(copies, imported);
}

/** Phase 232. Flag off leaves dynamic specifiers unseen, as the current walker does. */
export function dynamicImportSpec(
  flag: boolean,
  source: string,
  alreadyImported: readonly string[] = [],
): DynamicSpec[] {
  const known = new Set(alreadyImported);
  return collectDynamic(source).map((hit) => applyDynamic(flag, hit, known));
}

/** Phase 233. No `exports`, or the flag off, keeps today's import-level reach. */
export function exportMapAllows(flag: boolean, exportsField: unknown, specifier: string): boolean {
  if (!flag || exportsField === undefined) {return true;}
  const sub = subpathOf(specifier);
  if (sub === undefined || sub === '.') {return rootExportAllows(exportsField);}
  return deepExportAllows(exportsField, sub);
}

/** Phase 234. Flag off ignores conditions. Electron uses the Phase 102 detector. */
export function conditionAllows(
  flag: boolean,
  value: unknown,
  request: 'import' | 'require',
  deps?: RuntimeDeps,
): boolean {
  if (!flag) {return true;}
  return resolveConditions(value, request, deps, 0);
}

/** Phase 235. The script class is flag-only. Flag off returns `current`. */
export function scriptReach(
  flag: boolean,
  scripts: Readonly<Record<string, string>> | undefined,
  bin: string | Readonly<Record<string, string>> | undefined,
  packageName: string,
  current: ImportReach = 'not-imported',
): ImportReach | 'reachable-via-script' {
  if (!flag) {return current;}
  return scriptNamesPackage(scripts, bin, packageName) ? 'reachable-via-script' : current;
}

/** Phase 236. A literal Worker or fork is a call. A bare string is not. */
export function workerSpec(flag: boolean, source: string): WorkerHit[] {
  return collectWorker(source).map((hit) => applyWorker(flag, hit));
}

/** Phase 237. No advisory file stays import-level. Phase 233 blocks a missing subpath only when its flag is on. */
export function subpathExport(
  flag: boolean,
  exportsField: unknown,
  specifier: string,
  advisoryFile: string | undefined,
  exportsFlag: boolean,
): SubpathResult {
  if (!flag) {return { kind: 'import' };}
  const sub = subpathOf(specifier);
  if (sub === undefined || sub === '.') {return { kind: 'import' };}
  if (exportsFlag && !exportMapAllows(true, exportsField, specifier)) {return { kind: 'not-a-reach' };}
  return symbolOrImport(exportsField, sub, advisoryFile);
}

/** Phase 239. `export type` is not an import. Depth above 5 does not extend the walk. */
export function reexportSpec(flag: boolean, source: string, depth = 1): ReexportHit[] {
  return collectReexports(source).map((hit) => ({
    name: hit.name,
    typeOnly: hit.typeOnly,
    countsAsImport: flag && depth <= 5 && !hit.typeOnly && hit.name !== undefined,
  }));
}

/** Phase 240. Flag off still counts `import type`. A value import stays a reach. */
export function typeOnlyImport(flag: boolean, source: string): TypeImportHit[] {
  return collectTypeImports(source).map((hit) => ({
    name: hit.name,
    typeOnly: hit.typeOnly,
    countsAsImport: hit.typeOnly ? !flag : true,
  }));
}

/**
 * Phase 238. A require in try/catch stays imported.
 * `optionalImport` is set only when this phase and Phase 61 evidence are both requested.
 * It is not attached to vulnerability rows.
 */
export function tryRequireEvidence(reachTry: boolean, evidenceFlag: boolean, source: string): TryRequireHit[] {
  const ranges = tryRanges(source);
  const out: TryRequireHit[] = [];
  for (const hit of literalRequires(source)) {
    const row: TryRequireHit = { name: hit.name, line: lineAt(source, hit.index), imported: true };
    if (reachTry && evidenceFlag && indexInRanges(hit.index, ranges)) {row.optionalImport = true;}
    out.push(row);
  }
  return out;
}

/** Phases 229–231 and 241–242. Reachability-class phases stay pure and emit nothing. */
export async function laneFindings(input: NpmDepthInput): Promise<Finding[]> {
  const out: Finding[] = [];
  const lock = npmLock(input);
  if (npmFlag('NPM_GRAPH_OPTIONAL')) {out.push(...optionalFindings(lock, input.manifestRaw));}
  if (npmFlag('NPM_GRAPH_PEER')) {out.push(...peerFindings(lock, input.manifestRaw));}
  if (npmFlag('NPM_GRAPH_ALIAS')) {out.push(...aliasFindings(lock, input.manifestRaw));}
  if (npmFlag('NPM_DUALPACKAGE')) {out.push(...(await dualFindings(input, lock)));}
  if (npmFlag('NPM_PHANTOM_DEEP')) {out.push(...(await phantomFindings(input)));}
  return out;
}

function importedMap(roots: readonly ImportedRoot[]): Map<string, boolean> {
  const map = new Map<string, boolean>();
  for (const root of roots) {
    map.set(root.name, map.get(root.name) === true || root.called);
  }
  return map;
}

function directClass(called: boolean): 'reachable' | 'imported-not-called' {
  return called ? 'reachable' : 'imported-not-called';
}

function buildNameEdges(copies: readonly GraphCopy[]): Map<string, Set<string>> {
  const nameByPath = new Map(copies.map((copy) => [copy.path, copy.name]));
  const edges = new Map<string, Set<string>>();
  for (const copy of copies) {
    for (const parent of copy.requiredBy) {
      const parentName = nameByPath.get(parent) ?? bareParent(parent);
      if (parentName === undefined || parentName === copy.name) {continue;}
      const set = edges.get(parentName) ?? new Set<string>();
      set.add(copy.name);
      edges.set(parentName, set);
    }
  }
  return edges;
}

function bareParent(parent: string): string | undefined {
  return parent.includes('node_modules/') ? undefined : parent;
}

function reachableNames(roots: readonly string[], edges: Map<string, Set<string>>): Set<string> {
  const seen = new Set<string>();
  const queue = [...roots];
  while (queue.length > 0) {
    const name = queue.shift();
    if (name === undefined) {continue;}
    for (const next of edges.get(name) ?? []) {
      if (seen.has(next)) {continue;}
      seen.add(next);
      queue.push(next);
    }
  }
  return seen;
}

function classifyByName(copies: readonly GraphCopy[], imported: ReadonlyMap<string, boolean>): InstanceClass[] {
  const reached = reachableNames([...imported.keys()], buildNameEdges(copies));
  return copies.map((copy) => ({
    path: copy.path,
    name: copy.name,
    reachability: nameClass(copy.name, imported, reached),
  }));
}

function nameClass(name: string, imported: ReadonlyMap<string, boolean>, reached: ReadonlySet<string>): ImportReach {
  const called = imported.get(name);
  if (called !== undefined) {return directClass(called);}
  return reached.has(name) ? 'reachable-via-dependency' : 'not-imported';
}

function isDirectCopy(copy: GraphCopy, copies: readonly GraphCopy[]): boolean {
  if (copy.path === `node_modules/${copy.name}`) {return true;}
  return copies.filter((item) => item.name === copy.name).length === 1;
}

function classifyByPath(copies: readonly GraphCopy[], imported: ReadonlyMap<string, boolean>): InstanceClass[] {
  const reach = new Map<string, ImportReach>();
  const queue: string[] = [];
  seedDirect(copies, imported, reach, queue);
  walkRequired(copies, reach, queue);
  return copies.map((copy) => ({
    path: copy.path,
    name: copy.name,
    reachability: reach.get(copy.path) ?? 'not-imported',
  }));
}

function seedDirect(
  copies: readonly GraphCopy[],
  imported: ReadonlyMap<string, boolean>,
  reach: Map<string, ImportReach>,
  queue: string[],
): void {
  for (const copy of copies) {
    const called = imported.get(copy.name);
    if (called === undefined || !isDirectCopy(copy, copies)) {continue;}
    reach.set(copy.path, directClass(called));
    queue.push(copy.path);
  }
}

function walkRequired(copies: readonly GraphCopy[], reach: Map<string, ImportReach>, queue: string[]): void {
  let guard = 0;
  while (queue.length > 0 && guard < 10000) {
    guard += 1;
    const path = queue.shift();
    if (path === undefined) {continue;}
    enqueueChildren(copies, path, reach, queue);
  }
}

function enqueueChildren(
  copies: readonly GraphCopy[],
  path: string,
  reach: Map<string, ImportReach>,
  queue: string[],
): void {
  for (const copy of copies) {
    if (reach.has(copy.path) || !copy.requiredBy.includes(path)) {continue;}
    reach.set(copy.path, 'reachable-via-dependency');
    queue.push(copy.path);
  }
}

function packageNameOf(spec: string): string | undefined {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) {return undefined;}
  if (BUILTINS.has(spec)) {return undefined;}
  if (spec.startsWith('@')) {
    const parts = spec.split('/');
    const name = parts.length >= 2 ? `${parts[0]}/${parts[1]}` : undefined;
    return name !== undefined && !BUILTINS.has(name) ? name : undefined;
  }
  const name = spec.split('/')[0];
  if (name === undefined || name.length === 0 || BUILTINS.has(name)) {return undefined;}
  return name;
}

function lineAt(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (source.charCodeAt(i) === 10) {line += 1;}
  }
  return line;
}

function collectPattern(source: string, re: RegExp, literal: boolean, group: number, out: RawCall[]): void {
  re.lastIndex = 0;
  let match: RegExpExecArray | null = re.exec(source);
  while (match !== null) {
    const spec = match[group];
    if (spec !== undefined && match.index !== undefined) {
      const name = literal ? packageNameOf(spec) : undefined;
      if (!literal || name !== undefined) {out.push({ name, literal, index: match.index });}
    }
    match = re.exec(source);
  }
}

function collectDynamic(source: string): RawCall[] {
  const out: RawCall[] = [];
  collectPattern(source, /\bimport\s*\(\s*(['"])([^'"]+)\1\s*\)/g, true, 2, out);
  collectPattern(source, /\brequire\.resolve\s*\(\s*(['"])([^'"]+)\1\s*\)/g, true, 2, out);
  collectPattern(source, /\bcreateRequire\s*\([^)]*\)\s*\(\s*(['"])([^'"]+)\1\s*\)/g, true, 2, out);
  collectPattern(source, /\bimport\s*\(\s*([^'")\s][^)]*)\)/g, false, 1, out);
  collectPattern(source, /\brequire\.resolve\s*\(\s*([^'")\s][^)]*)\)/g, false, 1, out);
  collectPattern(source, /\bcreateRequire\s*\([^)]*\)\s*\(\s*([^'")\s][^)]*)\)/g, false, 1, out);
  return out;
}

function applyDynamic(flag: boolean, hit: RawCall, known: ReadonlySet<string>): DynamicSpec {
  if (!flag || !hit.literal) {return dynamicOff(flag, hit);}
  const alreadyCounted = hit.name !== undefined && known.has(hit.name);
  return { name: hit.name, literal: true, countsAsImport: !alreadyCounted, alreadyCounted };
}

function dynamicOff(flag: boolean, hit: RawCall): DynamicSpec {
  if (!flag) {return { name: hit.name, literal: hit.literal, countsAsImport: false, alreadyCounted: false };}
  return { literal: false, countsAsImport: false, reachability: 'reachability-unknown', alreadyCounted: false };
}

function subpathOf(specifier: string): string | undefined {
  if (specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('node:')) {return undefined;}
  const parts = specifier.split('/');
  if (specifier.startsWith('@')) {
    if (parts.length < 2) {return undefined;}
    return parts.length === 2 ? '.' : `./${parts.slice(2).join('/')}`;
  }
  return parts.length === 1 ? '.' : `./${parts.slice(1).join('/')}`;
}

function rootExportAllows(exportsField: unknown): boolean {
  if (typeof exportsField !== 'object' || exportsField === null || Array.isArray(exportsField)) {return true;}
  return (exportsField as Record<string, unknown>)['.'] !== null;
}

function deepExportAllows(exportsField: unknown, sub: string): boolean {
  if (typeof exportsField !== 'object' || exportsField === null || Array.isArray(exportsField)) {return false;}
  for (const [key, value] of Object.entries(exportsField as Record<string, unknown>)) {
    if (exportKeyMatches(key, sub)) {return value !== null;}
  }
  return false;
}

function exportKeyMatches(key: string, sub: string): boolean {
  if (key === sub) {return true;}
  const star = key.indexOf('*');
  if (star === -1) {return false;}
  const prefix = key.slice(0, star);
  const suffix = key.slice(star + 1);
  return sub.startsWith(prefix) && sub.endsWith(suffix) && sub.length >= prefix.length + suffix.length;
}

function electronRuntime(deps: RuntimeDeps | undefined): boolean {
  if (deps?.manifest !== undefined && packageUsesElectron(deps.manifest)) {return true;}
  return deps?.lockText !== undefined && lockUsesElectron(deps.lockText);
}

function conditionActive(key: string, request: 'import' | 'require', deps: RuntimeDeps | undefined): boolean {
  if (key === 'default' || key === 'node' || key === request) {return true;}
  if (key === 'react-native') {return deps?.packages?.includes('react-native') === true;}
  if (key === 'electron') {return electronRuntime(deps);}
  return false;
}

function resolveConditions(value: unknown, request: 'import' | 'require', deps: RuntimeDeps | undefined, depth: number): boolean {
  if (typeof value === 'string') {return true;}
  if (value === null || depth > 8 || typeof value !== 'object' || Array.isArray(value)) {return false;}
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (!conditionActive(key, request, deps)) {continue;}
    return resolveConditions(child, request, deps, depth + 1);
  }
  return false;
}

function binCommands(bin: string | Readonly<Record<string, string>> | undefined, packageName: string): Set<string> {
  if (typeof bin === 'string') {
    const base = packageName.startsWith('@') ? packageName.slice(packageName.indexOf('/') + 1) : packageName;
    return new Set([base]);
  }
  return new Set(bin === undefined ? [] : Object.keys(bin));
}

function bareCommand(part: string): string | undefined {
  const match = /^(?:[A-Za-z_][\w]*=\S*\s+)*(\S+)/.exec(part.trim());
  const token = match?.[1];
  if (token === undefined || token.includes('/') || token.includes('\\')) {return undefined;}
  return token;
}

function scriptNamesPackage(
  scripts: Readonly<Record<string, string>> | undefined,
  bin: string | Readonly<Record<string, string>> | undefined,
  packageName: string,
): boolean {
  const names = binCommands(bin, packageName);
  for (const value of Object.values(scripts ?? {})) {
    for (const part of value.split(/&&|\|\||[;|\n]/)) {
      const command = bareCommand(part);
      if (command !== undefined && names.has(command)) {return true;}
    }
  }
  return false;
}

function collectWorker(source: string): RawCall[] {
  const out: RawCall[] = [];
  collectPattern(source, /\bnew\s+Worker\s*\(\s*(['"])([^'"]+)\1/g, true, 2, out);
  collectPattern(source, /\bfork\s*\(\s*(['"])([^'"]+)\1/g, true, 2, out);
  collectPattern(source, /\bnew\s+Worker\s*\(\s*([^'")\s][^)]*)\)/g, false, 1, out);
  collectPattern(source, /\bfork\s*\(\s*([^'")\s][^)]*)\)/g, false, 1, out);
  return out;
}

function applyWorker(flag: boolean, hit: RawCall): WorkerHit {
  if (!flag) {return { name: hit.name, literal: hit.literal, countsAsCall: false };}
  if (!hit.literal) {return { literal: false, countsAsCall: false, reachability: 'reachability-unknown' };}
  return { name: hit.name, literal: true, countsAsCall: hit.name !== undefined };
}

function exportTarget(exportsField: unknown, sub: string): string | undefined {
  if (typeof exportsField !== 'object' || exportsField === null || Array.isArray(exportsField)) {return undefined;}
  for (const [key, value] of Object.entries(exportsField as Record<string, unknown>)) {
    if (exportKeyMatches(key, sub)) {return firstTarget(value);}
  }
  return undefined;
}

function firstTarget(value: unknown): string | undefined {
  if (typeof value === 'string') {return value;}
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
  const obj = value as Record<string, unknown>;
  for (const key of ['default', 'require', 'import', 'node']) {
    if (key in obj) {
      const found = firstTarget(obj[key]);
      if (found !== undefined) {return found;}
    }
  }
  for (const child of Object.values(obj)) {
    const found = firstTarget(child);
    if (found !== undefined) {return found;}
  }
  return undefined;
}

function fileMatches(target: string, advisoryFile: string): boolean {
  const norm = target.replace(/^\.\//, '');
  return norm === advisoryFile || advisoryFile.endsWith(norm) || norm.endsWith(advisoryFile);
}

function symbolOrImport(exportsField: unknown, sub: string, advisoryFile: string | undefined): SubpathResult {
  if (advisoryFile === undefined) {return { kind: 'import' };}
  const target = exportTarget(exportsField, sub);
  if (target !== undefined && fileMatches(target, advisoryFile)) {return { kind: 'symbol', target };}
  return { kind: 'import' };
}

interface RawReexport {
  name?: string;
  typeOnly: boolean;
}

function collectReexports(source: string): RawReexport[] {
  const out: RawReexport[] = [];
  collectExport(source, /\bexport\s+(type\s+)?\*\s+from\s+(['"])([^'"]+)\2/g, { type: 1, spec: 3 }, out);
  collectExport(source, /\bexport\s+(type\s+)?\{([^}]*)\}\s+from\s+(['"])([^'"]+)\3/g, { type: 1, spec: 4, inner: 2 }, out);
  return out;
}

function collectExport(
  source: string,
  re: RegExp,
  groups: { type: number; spec: number; inner?: number },
  out: RawReexport[],
): void {
  re.lastIndex = 0;
  let match: RegExpExecArray | null = re.exec(source);
  while (match !== null) {
    const spec = match[groups.spec];
    const inner = groups.inner === undefined ? undefined : match[groups.inner];
    if (spec !== undefined) {
      const prefixed = match[groups.type] !== undefined;
      out.push({ name: packageNameOf(spec), typeOnly: namedTypeOnly(inner, prefixed) });
    }
    match = re.exec(source);
  }
}

function namedTypeOnly(inner: string | undefined, prefixed: boolean): boolean {
  if (prefixed) {return true;}
  if (inner === undefined) {return false;}
  const parts = inner.split(',').map((part) => part.trim()).filter((part) => part.length > 0);
  return parts.length > 0 && parts.every((part) => part.startsWith('type '));
}

interface RawTypeImport {
  name: string;
  typeOnly: boolean;
}

function collectTypeImports(source: string): RawTypeImport[] {
  const out: RawTypeImport[] = [];
  pushType(source, /\bimport\s+type\s+[A-Za-z_$][\w$]*\s+from\s+(['"])([^'"]+)\1/g, 2, true, out);
  pushType(source, /\bimport\s+type\s+\{[^}]*\}\s+from\s+(['"])([^'"]+)\1/g, 2, true, out);
  pushType(source, /\bexport\s+type\s+(?:\*|\{[^}]*\})\s+from\s+(['"])([^'"]+)\1/g, 2, true, out);
  pushType(source, /\bimport\s+(?!type\b)([A-Za-z_$][\w$]*)\s+from\s+(['"])([^'"]+)\2/g, 3, false, out);
  pushNamedValues(source, out);
  return out;
}

function pushType(source: string, re: RegExp, group: number, typeOnly: boolean, out: RawTypeImport[]): void {
  re.lastIndex = 0;
  let match: RegExpExecArray | null = re.exec(source);
  while (match !== null) {
    const spec = match[group];
    const name = spec === undefined ? undefined : packageNameOf(spec);
    if (name !== undefined) {out.push({ name, typeOnly });}
    match = re.exec(source);
  }
}

function pushNamedValues(source: string, out: RawTypeImport[]): void {
  const re = /\bimport\s+\{([^}]*)\}\s+from\s+(['"])([^'"]+)\2/g;
  let match: RegExpExecArray | null = re.exec(source);
  while (match !== null) {
    const inner = match[1] ?? '';
    const spec = match[3];
    const name = spec === undefined ? undefined : packageNameOf(spec);
    if (name !== undefined) {out.push({ name, typeOnly: namedTypeOnly(inner, false) });}
    match = re.exec(source);
  }
}

function literalRequires(source: string): Array<{ name: string; index: number }> {
  const out: Array<{ name: string; index: number }> = [];
  const re = /\brequire\s*\(\s*(['"])([^'"]+)\1\s*\)/g;
  let match: RegExpExecArray | null = re.exec(source);
  while (match !== null) {
    const spec = match[2];
    const name = spec === undefined ? undefined : packageNameOf(spec);
    if (name !== undefined && match.index !== undefined) {out.push({ name, index: match.index });}
    match = re.exec(source);
  }
  return out;
}

function braceEnd(source: string, open: number): number | undefined {
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === '{') {depth += 1;}
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {return i;}
    }
  }
  return undefined;
}

function tryRanges(source: string): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = [];
  const re = /\btry\b/g;
  let match: RegExpExecArray | null = re.exec(source);
  while (match !== null) {
    const open = source.indexOf('{', match.index);
    const end = open === -1 ? undefined : braceEnd(source, open);
    if (open !== -1 && end !== undefined) {ranges.push({ start: open, end });}
    match = re.exec(source);
  }
  return ranges;
}

function indexInRanges(index: number, ranges: ReadonlyArray<{ start: number; end: number }>): boolean {
  return ranges.some((range) => index > range.start && index < range.end);
}

function npmLock(input: NpmDepthInput): { file: string; text: string; packages: Record<string, LockEntry> } | undefined {
  for (const file of ['package-lock.json', 'npm-shrinkwrap.json']) {
    const text = input.lockTexts[file];
    const packages = text === undefined ? undefined : packagesOf(text);
    if (text !== undefined && packages !== undefined) {return { file, text, packages };}
  }
  return undefined;
}

function packagesOf(text: string): Record<string, LockEntry> | undefined {
  try {
    const json = JSON.parse(text) as { packages?: unknown };
    if (json.packages === null || typeof json.packages !== 'object' || Array.isArray(json.packages)) {return undefined;}
    return json.packages as Record<string, LockEntry>;
  } catch {
    return undefined;
  }
}

function isPresent(packages: Record<string, LockEntry>, name: string): boolean {
  const needle = `node_modules/${name}`;
  return Object.keys(packages).some((key) => key === needle || key.endsWith(`/${needle}`));
}

function manifestRecord(raw: string | undefined, field: string): Record<string, unknown> {
  if (raw === undefined) {return {};}
  try {
    const manifest = JSON.parse(raw) as Record<string, unknown>;
    const block = manifest[field];
    if (block === null || typeof block !== 'object' || Array.isArray(block)) {return {};}
    return block as Record<string, unknown>;
  } catch {
    return {};
  }
}

function lineOfNeedle(text: string, needle: string): number | undefined {
  const index = text.split(/\r?\n/).findIndex((row) => row.includes(needle));
  return index >= 0 ? index + 1 : undefined;
}

function optionalFindings(
  lock: { file: string; text: string; packages: Record<string, LockEntry> } | undefined,
  manifestRaw: string | undefined,
): Finding[] {
  if (lock === undefined) {return [];}
  const missing = missingOptional(lock.packages, manifestRaw);
  return missing.map((name) => optionalFinding(lock, name));
}

function missingOptional(packages: Record<string, LockEntry>, manifestRaw: string | undefined): string[] {
  const missing = new Set<string>();
  for (const entry of Object.values(packages)) {
    for (const name of Object.keys(entry.optionalDependencies ?? {})) {
      if (!isPresent(packages, name)) {missing.add(name);}
    }
  }
  for (const name of Object.keys(manifestRecord(manifestRaw, 'optionalDependencies'))) {
    if (!isPresent(packages, name)) {missing.add(name);}
  }
  return [...missing].sort();
}

function optionalFinding(
  lock: { file: string; text: string; packages: Record<string, LockEntry> },
  name: string,
): Finding {
  return {
    ...npmFinding(
      OPTIONAL_ID,
      'info',
      lock.file,
      name,
      `Optional dependency ${name} is missing`,
      `Optional dependency ${name} is missing from the lock. Its parent stays imported.`,
      `Install ${name}, or remove it from optionalDependencies.`,
    ),
    line: lineOfNeedle(lock.text, `"${name}"`),
  };
}

function peerFindings(
  lock: { file: string; text: string; packages: Record<string, LockEntry> } | undefined,
  manifestRaw: string | undefined,
): Finding[] {
  if (lock === undefined) {return [];}
  return missingPeers(lock.packages, manifestRaw).map((name) => peerFinding(lock, name));
}

function missingPeers(packages: Record<string, LockEntry>, manifestRaw: string | undefined): string[] {
  const missing = new Set<string>();
  for (const entry of Object.values(packages)) {
    addMissingPeers(packages, entry.peerDependencies, entry.peerDependenciesMeta, missing);
  }
  addMissingPeers(
    packages,
    manifestRecord(manifestRaw, 'peerDependencies'),
    manifestRecord(manifestRaw, 'peerDependenciesMeta') as LockEntry['peerDependenciesMeta'],
    missing,
  );
  return [...missing].sort();
}

function addMissingPeers(
  packages: Record<string, LockEntry>,
  peers: Record<string, unknown> | undefined,
  meta: LockEntry['peerDependenciesMeta'],
  missing: Set<string>,
): void {
  for (const name of Object.keys(peers ?? {})) {
    if (meta?.[name]?.optional === true || isPresent(packages, name)) {continue;}
    missing.add(name);
  }
}

function peerFinding(lock: { file: string; text: string }, name: string): Finding {
  return {
    ...npmFinding(
      PEER_ID,
      'medium',
      lock.file,
      name,
      `Peer dependency ${name} is missing`,
      `Non-optional peer ${name} is absent from the lock.`,
      `Add ${name} to the root dependencies so the lock installs it, or declare the peer optional.`,
    ),
    line: lineOfNeedle(lock.text, `"${name}"`),
  };
}

function aliasFindings(
  lock: { file: string; text: string; packages: Record<string, LockEntry> } | undefined,
  manifestRaw: string | undefined,
): Finding[] {
  const aliases = new Map<string, string>();
  collectManifestAliases(manifestRaw, aliases);
  if (lock !== undefined) {collectLockAliases(lock.packages, aliases);}
  const file = lock?.file ?? 'package.json';
  const text = lock?.text ?? manifestRaw ?? '';
  return [...aliases.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([alias, target]) => aliasFinding(file, text, alias, target));
}

function collectManifestAliases(raw: string | undefined, aliases: Map<string, string>): void {
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [alias, spec] of Object.entries(manifestRecord(raw, field))) {
      rememberAlias(aliases, alias, spec);
    }
  }
}

function collectLockAliases(packages: Record<string, LockEntry>, aliases: Map<string, string>): void {
  for (const [key, entry] of Object.entries(packages)) {
    rememberEntryName(aliases, key, entry);
    for (const block of [entry.dependencies, entry.optionalDependencies, entry.peerDependencies]) {
      for (const [alias, spec] of Object.entries(block ?? {})) {rememberAlias(aliases, alias, spec);}
    }
  }
}

function rememberAlias(aliases: Map<string, string>, alias: string, spec: unknown): void {
  if (typeof spec !== 'string') {return;}
  const target = npmAliasTarget(spec);
  if (target !== undefined) {aliases.set(alias, target);}
}

function rememberEntryName(aliases: Map<string, string>, key: string, entry: LockEntry): void {
  if (key === '' || entry.name === undefined) {return;}
  const alias = nameFromLockPath(key);
  if (alias !== undefined && alias !== entry.name) {aliases.set(alias, entry.name);}
}

function npmAliasTarget(spec: string): string | undefined {
  if (!spec.startsWith('npm:')) {return undefined;}
  const rest = spec.slice('npm:'.length);
  if (rest.startsWith('@')) {
    const slash = rest.indexOf('/');
    if (slash === -1) {return undefined;}
    const at = rest.indexOf('@', slash + 1);
    return at === -1 ? rest : rest.slice(0, at);
  }
  const at = rest.indexOf('@');
  return at === -1 ? rest : rest.slice(0, at);
}

function nameFromLockPath(key: string): string | undefined {
  const idx = key.lastIndexOf('node_modules/');
  if (idx === -1) {return undefined;}
  const name = key.slice(idx + 'node_modules/'.length);
  return name.length > 0 ? name : undefined;
}

function aliasFinding(file: string, text: string, alias: string, target: string): Finding {
  const snippet = `${alias} → ${target}`;
  return {
    ...npmFinding(
      ALIAS_ID,
      'info',
      file,
      snippet,
      `Alias ${alias} resolves to ${target}`,
      `${alias} → ${target}. Imports of the alias name follow ${target}. Advisory rows stay on the target version.`,
      `Confirm ${alias} is meant to install ${target}.`,
    ),
    line: lineOfNeedle(text, `"${alias}"`),
  };
}

async function dualFindings(
  input: NpmDepthInput,
  lock: { file: string; packages: Record<string, LockEntry> } | undefined,
): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const source of await sourceTexts(input)) {
    for (const hit of literalRequires(source.text)) {
      const row = await dualFinding(input, lock, source.file, source.text, hit);
      if (row !== undefined) {out.push(row);}
    }
  }
  return out;
}

async function dualFinding(
  input: NpmDepthInput,
  lock: { packages: Record<string, LockEntry> } | undefined,
  file: string,
  text: string,
  hit: { name: string; index: number },
): Promise<Finding | undefined> {
  const packument = await readPackument(input, lock, hit.name);
  if (packument === undefined || packument.type !== 'module') {return undefined;}
  if (hasRequireCondition(rootExportValue(packument.exports))) {return undefined;}
  return {
    ...npmFinding(
      DUAL_ID,
      'medium',
      file,
      hit.name,
      `CommonJS require of ESM-only ${hit.name}`,
      `require('${hit.name}') targets a package whose type is module and whose exports have no require condition.`,
      `Import ${hit.name} from ESM, or depend on a build that publishes a require condition.`,
    ),
    line: lineAt(text, hit.index),
  };
}

function rootExportValue(exportsField: unknown): unknown {
  if (typeof exportsField !== 'object' || exportsField === null || Array.isArray(exportsField)) {return exportsField;}
  const obj = exportsField as Record<string, unknown>;
  if ('.' in obj) {return obj['.'];}
  const keys = Object.keys(obj);
  if (keys.length > 0 && keys.every((key) => key.startsWith('.'))) {return undefined;}
  return obj;
}

function hasRequireCondition(value: unknown, depth = 0): boolean {
  if (depth > 8 || value === null || typeof value !== 'object' || Array.isArray(value)) {return false;}
  const obj = value as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(obj, 'require') && obj.require !== null) {return true;}
  return Object.entries(obj).some(([key, child]) => !key.startsWith('.') && hasRequireCondition(child, depth + 1));
}

async function readPackument(
  input: NpmDepthInput,
  lock: { packages: Record<string, LockEntry> } | undefined,
  name: string,
): Promise<{ type?: string; exports?: unknown } | undefined> {
  const installed = await readInstalled(input.cwd, name);
  if (installed !== undefined) {return installed;}
  return readCached(input.cacheDir, name, lockedVersion(lock, name));
}

async function readInstalled(cwd: string, name: string): Promise<{ type?: string; exports?: unknown } | undefined> {
  try {
    const raw = JSON.parse(await readFile(join(cwd, 'node_modules', ...name.split('/'), 'package.json'), 'utf8')) as {
      type?: unknown;
      exports?: unknown;
    };
    return { type: typeof raw.type === 'string' ? raw.type : undefined, exports: raw.exports };
  } catch {
    return undefined;
  }
}

function lockedVersion(lock: { packages: Record<string, LockEntry> } | undefined, name: string): string | undefined {
  const version = lock?.packages[`node_modules/${name}`]?.version;
  return typeof version === 'string' ? version : undefined;
}

async function readCached(
  cacheDir: string,
  name: string,
  version: string | undefined,
): Promise<{ type?: string; exports?: unknown } | undefined> {
  try {
    const raw = JSON.parse(await readFile(registryCachePath(cacheDir, name), 'utf8')) as Record<string, unknown>;
    const body = versionEntry(raw, version) ?? asPackageJson(raw);
    if (body === undefined) {return undefined;}
    return { type: typeof body.type === 'string' ? body.type : undefined, exports: body.exports };
  } catch {
    return undefined;
  }
}

function versionEntry(raw: Record<string, unknown>, version: string | undefined): Record<string, unknown> | undefined {
  const packument = asRecord(raw.packument) ?? raw;
  const versions = asRecord(packument.versions);
  if (version === undefined || versions === undefined) {return undefined;}
  return asRecord(versions[version]);
}

function asPackageJson(raw: Record<string, unknown>): Record<string, unknown> | undefined {
  const packument = asRecord(raw.packument) ?? raw;
  if (typeof packument.type === 'string' || packument.exports !== undefined) {return packument;}
  return undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
  return value as Record<string, unknown>;
}

async function phantomFindings(input: NpmDepthInput): Promise<Finding[]> {
  const declared = declaredNames(input.manifestRaw);
  const out: Finding[] = [];
  for (const source of await sourceTexts(input)) {
    for (const hit of collectDynamic(source.text)) {
      if (!hit.literal || hit.name === undefined || declared.has(hit.name)) {continue;}
      out.push(phantomFinding(source.file, source.text, hit));
    }
  }
  return out;
}

function declaredNames(raw: string | undefined): Set<string> {
  const names = new Set<string>();
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const name of Object.keys(manifestRecord(raw, field))) {names.add(name);}
  }
  return names;
}

function phantomFinding(file: string, text: string, hit: RawCall): Finding {
  const name = hit.name ?? '';
  return {
    ...npmFinding(
      PHANTOM_ID,
      'medium',
      file,
      name,
      `Dynamic import ${name} is not declared`,
      `A literal dynamic import names ${name}, which is not in dependencies, devDependencies, optionalDependencies, or peerDependencies.`,
      `Add ${name} to package.json, or remove the dynamic import.`,
    ),
    line: lineAt(text, hit.index),
  };
}

async function sourceTexts(input: NpmDepthInput): Promise<Array<{ file: string; text: string }>> {
  const out: Array<{ file: string; text: string }> = [];
  for (const file of input.files) {
    if (!sourceFile(file)) {continue;}
    try {
      out.push({ file, text: await readFile(join(input.cwd, file), 'utf8') });
    } catch {
      // unreadable source is not a graph finding
    }
  }
  return out;
}

function sourceFile(file: string): boolean {
  if (file.split('/').includes('node_modules')) {return false;}
  return /\.[cm]?[jt]sx?$/.test(file);
}
