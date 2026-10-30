/**
 * Phase 572. Section H package and framework checks.
 * Off unless FULLSHIELD_EXPERIMENTAL_SECTIONG=1.
 * Flag off does not read the project and does not add a finding.
 */
import { readdir, readFile } from 'node:fs/promises';
import { extname, join, relative } from 'node:path';

import type { ScanResult } from '../core/engine.js';
import { makeFindingId, type Finding, type Severity } from '../core/finding.js';
import { withExtraFindings } from '../modules/sast/parity.js';

const SECTIONG_FLAG = 'FULLSHIELD_EXPERIMENTAL_SECTIONG';
const SKIP = new Set(['node_modules', '.git', 'dist', 'coverage', '.fullshield']);
const SOURCE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const LOCKS = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']);
const HIDDEN = ['\u202e', '\u200b'];

interface Loaded {
  rel: string;
  name: string;
  text: string;
}

interface Doc {
  name?: string;
  private?: boolean;
  files?: string[];
  workspaces?: string[];
  scripts?: Record<string, string>;
  engines?: { node?: string };
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface Hit {
  n: string;
  severity: Severity;
  title: string;
  message: string;
  needle: string;
}

function on(): boolean {
  return process.env[SECTIONG_FLAG] === '1';
}

function hid(n: string): string {
  return ['SECT', 'H', n].join('-');
}

function has(text: string, needle: string): boolean {
  return text.includes(needle);
}

function lineOf(text: string, needle: string): number {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if ((lines[i] ?? '').includes(needle)) {return i + 1;}
  }
  return 1;
}

function majorOf(version: string): string {
  return /(\d+)/.exec(version)?.[1] ?? '';
}

function hidden(text: string): boolean {
  return HIDDEN.some((ch) => text.includes(ch));
}

function row(file: string, text: string, hit: Hit): Finding {
  const line = lineOf(text, hit.needle);
  const snippet = text.split(/\r?\n/)[line - 1] ?? hit.needle;
  const ruleId = hid(hit.n);
  return {
    id: makeFindingId(ruleId, file, snippet),
    ruleId,
    module: 'sast',
    title: hit.title,
    severity: hit.severity,
    confidence: 'low',
    file,
    line,
    snippet,
    message: hit.message,
    remediation: 'Review this experimental section H check. It is off unless the section G flag is set.',
    source: 'rule',
  };
}

function add(hits: Finding[], file: string, text: string, ok: boolean, hit: Hit): void {
  if (ok) {hits.push(row(file, text, hit));}
}

function parseDoc(text: string): Doc | undefined {
  try {
    return JSON.parse(text) as Doc;
  } catch {
    return undefined;
  }
}

function scriptOf(doc: Doc, keys: readonly string[]): string {
  const scripts = doc.scripts ?? {};
  return keys.map((key) => scripts[key] ?? '').join('\n');
}

function lockMap(text: string): Map<string, string> {
  const map = new Map<string, string>();
  const doc = parseDoc(text) as { packages?: Record<string, { version?: string }> } | undefined;
  for (const [key, value] of Object.entries(doc?.packages ?? {})) {
    const name = key.replace(/^node_modules\//, '');
    if (name.length > 0 && value.version !== undefined) {map.set(name, value.version);}
  }
  return map;
}

function yarnMap(text: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const block of text.split(/\n\n/)) {
    const name = /^"?(@?[^@"\n]+)@/.exec(block)?.[1];
    const version = /version "?([^"\s]+)"?/.exec(block)?.[1];
    if (name !== undefined && version !== undefined) {map.set(name, version);}
  }
  return map;
}

function pnpmMap(text: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const match of text.matchAll(/\/(@?[^/@\n]+)@(\d+\.\d+\.\d+)/g)) {
    const name = match[1];
    const version = match[2];
    if (name !== undefined && version !== undefined) {map.set(name, version);}
  }
  return map;
}

function hiddenJs(file: Loaded, hits: Finding[]): void {
  const source = SOURCE_EXT.has(extname(file.name));
  add(hits, file.rel, file.text, source && hidden(file.text), {
    n: '001', severity: 'medium', title: 'Hidden character in source', message: 'A JavaScript string contains a hidden character.', needle: HIDDEN.find((ch) => file.text.includes(ch)) ?? '',
  });
}

function hiddenUrl(file: Loaded, hits: Finding[]): void {
  const lock = LOCKS.has(file.name) && has(file.text, '://') && hidden(file.text);
  add(hits, file.rel, file.text, lock, {
    n: '001', severity: 'medium', title: 'Hidden character in a lockfile URL', message: 'A lockfile URL contains a hidden character.', needle: '://',
  });
}

function patchSink(file: Loaded, hits: Finding[]): void {
  const text = file.text;
  const sink = has(text, 'query(') || has(text, 'exec(') || has(text, 'send(');
  const ok = file.rel.includes('patches/') && (has(text, 'req.body') || has(text, 'req.query')) && sink;
  add(hits, file.rel, text, ok, {
    n: '007', severity: 'medium', title: 'Patch reintroduces a sink', message: 'A patch passes request data into a sink.', needle: 'req.',
  });
}

function leakName(value: string): boolean {
  return has(value, '.env') || has(value, 'id_rsa') || has(value, '.github');
}

function filesLeak(file: Loaded, hits: Finding[]): void {
  if (file.name !== 'package.json') {return;}
  const doc = parseDoc(file.text);
  const listed = (doc?.files ?? []).some((entry) => leakName(entry));
  add(hits, file.rel, file.text, listed, {
    n: '008', severity: 'medium', title: 'Publish would pack a private file', message: 'files would pack a private path.', needle: 'files',
  });
}

function ignoreLeak(file: Loaded, hits: Finding[]): void {
  if (file.name !== '.npmignore') {return;}
  const listed = file.text.split(/\r?\n/).some((line) => {
    const trimmed = line.trim();
    return trimmed.length > 0 && !trimmed.startsWith('!') && leakName(trimmed);
  });
  add(hits, file.rel, file.text, listed, {
    n: '008', severity: 'medium', title: 'Publish would pack a private file', message: '.npmignore names a private path without negating it.', needle: '.env',
  });
}

function privateWorkspace(file: Loaded, hits: Finding[]): void {
  if (file.name !== 'package.json') {return;}
  const doc = parseDoc(file.text);
  const spaces = doc?.workspaces ?? [];
  const ok = doc?.name !== undefined && spaces.includes(doc.name) && doc.private !== true;
  add(hits, file.rel, file.text, ok, {
    n: '009', severity: 'low', title: 'Workspace is not private', message: 'A workspace package is not marked private.', needle: 'workspaces',
  });
}

function installFetch(file: Loaded, hits: Finding[]): void {
  if (file.name !== 'package.json') {return;}
  const doc = parseDoc(file.text);
  if (doc === undefined) {return;}
  const text = scriptOf(doc, ['preinstall', 'install', 'postinstall']);
  add(hits, file.rel, file.text, has(text, 'curl') || has(text, 'wget'), {
    n: '010', severity: 'medium', title: 'Install script downloads a URL', message: 'An install script names curl or wget. The script was not executed.', needle: 'curl',
  });
}

function hashMissing(text: string): boolean {
  return (has(text, 'http://') || has(text, 'https://')) && !has(text, 'integrity') && !has(text, 'sha256');
}

function binaryFetch(file: Loaded, hits: Finding[]): void {
  const doc = file.name === 'package.json' ? parseDoc(file.text) : undefined;
  const script = doc === undefined ? '' : Object.values(doc.scripts ?? {}).join('\n');
  const config = file.name.includes('config') && file.name !== 'package.json';
  const text = config ? file.text : script;
  add(hits, file.rel, file.text, text.length > 0 && hashMissing(text), {
    n: '011', severity: 'low', title: 'Download with no hash', message: 'A script or config fetches a URL and has no integrity pin.', needle: 'http',
  });
}

function loaderScript(file: Loaded, hits: Finding[]): void {
  if (file.name !== 'package.json') {return;}
  const doc = parseDoc(file.text);
  if (doc === undefined) {return;}
  const text = scriptOf(doc, ['start', 'preinstall', 'install', 'postinstall']);
  add(hits, file.rel, file.text, has(text, '--require') || has(text, 'NODE_OPTIONS'), {
    n: '012', severity: 'low', title: 'Script injects a loader', message: 'A start or install script sets a loader.', needle: 'NODE_OPTIONS',
  });
}

function nodeDrift(pkg: string, note: string | undefined, hits: Finding[], file: string): void {
  if (note === undefined) {return;}
  const doc = parseDoc(pkg);
  const engines = String(doc?.engines?.node ?? '');
  const differ = engines.length > 0 && majorOf(engines) !== majorOf(note);
  add(hits, file, pkg, differ, {
    n: '013', severity: 'low', title: 'Node version drift', message: 'engines.node and the version file name different majors.', needle: 'node',
  });
}

function imported(text: string): string[] {
  const names: string[] = [];
  for (const match of text.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)|from\s*['"]([^'"]+)['"]/g)) {
    const spec = match[1] ?? match[2] ?? '';
    if (spec.length === 0 || spec.startsWith('.')) {continue;}
    names.push(spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : (spec.split('/')[0] ?? spec));
  }
  return names;
}

function devImport(file: Loaded, doc: Doc | undefined, hits: Finding[]): void {
  if (extname(file.name) !== '.js' || doc === undefined) {return;}
  const deps = doc.dependencies ?? {};
  const dev = doc.devDependencies ?? {};
  const hit = imported(file.text).some((name) => dev[name] !== undefined && deps[name] === undefined);
  add(hits, file.rel, file.text, hit, {
    n: '014', severity: 'low', title: 'Production import of a devDependency', message: 'Production code imports a devDependency.', needle: 'require',
  });
}

function rawSql(file: Loaded, hits: Finding[]): void {
  const text = file.text;
  const tool = has(text, 'knex') || has(text, 'sequelize') || has(text, 'typeorm');
  const call = has(text, '.raw(') || has(text, 'sequelize.query(') || has(text, 'createQueryBuilder(');
  add(hits, file.rel, text, tool && has(text, 'req.') && call && !has(text, '$1'), {
    n: '016', severity: 'medium', title: 'Raw query from the request', message: 'Request data is passed into a raw query.', needle: 'req.',
  });
}

function mongo(file: Loaded, hits: Finding[]): void {
  const text = file.text;
  const where = has(text, '$where') || (has(text, 'mongoose') && has(text, '.where('));
  add(hits, file.rel, text, has(text, 'req.') && where, {
    n: '017', severity: 'medium', title: 'Mongo query from the request', message: 'Request data is used in a Mongo query.', needle: 'req.',
  });
}

function socketSink(text: string): boolean {
  const open = has(text, "socket.on('message'") || has(text, 'socket.on("connection"');
  if (!open) {return false;}
  if (has(text, 'query(') || has(text, 'exec(')) {return true;}
  return /send\(\s*[^'")\s]/.test(text);
}

function socket(file: Loaded, hits: Finding[]): void {
  add(hits, file.rel, file.text, socketSink(file.text), {
    n: '018', severity: 'low', title: 'Socket payload reaches a sink', message: 'A socket payload is passed to a sink.', needle: 'socket.on',
  });
}

function rewrite(file: Loaded, hits: Finding[]): void {
  const text = file.text;
  const route = has(text, 'redirects') || has(text, 'rewrites');
  const field = has(text, 'destination') || has(text, 'source');
  add(hits, file.rel, text, route && has(text, 'req.query') && field, {
    n: '019', severity: 'medium', title: 'Rewrite uses the query string', message: 'A rewrite or redirect copies the query string.', needle: 'req.query',
  });
}

function matcher(file: Loaded, hits: Finding[]): void {
  const text = file.text;
  const wide = has(text, 'matcher') && has(text, '/:path*');
  const action = has(text, 'use server') && has(text, 'searchParams') && !has(text, 'origin');
  add(hits, file.rel, text, wide || action, {
    n: '020', severity: 'low', title: 'Wide matcher or server action', message: 'A matcher is open, or a server action does not read origin.', needle: 'matcher',
  });
}

function framework(file: Loaded, hits: Finding[]): void {
  const text = file.text;
  const kind = (has(text, 'loader') || has(text, 'action')) && (has(text, 'LoaderFunction') || has(text, 'astro'));
  const sink = has(text, 'query(') || has(text, 'send(');
  add(hits, file.rel, text, kind && has(text, 'request.') && sink, {
    n: '021', severity: 'low', title: 'Framework request reaches a sink', message: 'A loader or action passes the request to a sink.', needle: 'request.',
  });
}

function fastify(file: Loaded, hits: Finding[]): void {
  const text = file.text;
  const route = has(text, 'fastify') && (has(text, '.post(') || has(text, '.put('));
  add(hits, file.rel, text, route && has(text, 'request.body') && has(text, 'query(') && !has(text, 'schema'), {
    n: '022', severity: 'low', title: 'Fastify body has no schema', message: 'A Fastify body reaches a query and the file has no schema.', needle: 'request.body',
  });
}

function graphql(file: Loaded, hits: Finding[]): void {
  if (file.rel.includes('test')) {return;}
  const text = file.text;
  const open = has(text, 'introspection: true') || !has(text, 'depthLimit');
  add(hits, file.rel, text, has(text, 'graphql') && open, {
    n: '023', severity: 'low', title: 'GraphQL production default', message: 'GraphQL introspection is on, or no depth limit is set.', needle: 'graphql',
  });
}

function listen(file: Loaded, hits: Finding[]): void {
  add(hits, file.rel, file.text, has(file.text, '.listen(') && !has(file.text, 'helmet'), {
    n: '024', severity: 'low', title: 'Listen without helmet', message: 'An app listens and this file does not call helmet.', needle: '.listen(',
  });
}

function digitsOver(text: string, key: string): boolean {
  for (const match of text.matchAll(new RegExp(`${key}\\s*:\\s*['"]?(\\d+)`, 'g'))) {
    if (Number(match[1]) > 100) {return true;}
  }
  return false;
}

function bodyLimit(file: Loaded, hits: Finding[]): void {
  const text = file.text;
  const bare = has(text, 'express.json(') && !/express\.json\(\s*\{[^}]*limit/.test(text);
  add(hits, file.rel, text, bare || digitsOver(text, 'limit') || digitsOver(text, 'bodyLimit'), {
    n: '026', severity: 'low', title: 'Body limit is missing or large', message: 'A body parser limit is missing or above the note.', needle: 'express.json',
  });
}

function debugRoute(file: Loaded, hits: Finding[]): void {
  const text = file.text;
  const surface = has(text, 'swagger') || has(text, 'graphql-playground') || has(text, "'/metrics'");
  add(hits, file.rel, text, surface && !has(text, 'auth'), {
    n: '027', severity: 'low', title: 'Debug surface without auth', message: 'A debug route is registered and this file does not mention auth.', needle: 'metrics',
  });
}

function sourceChecks(file: Loaded, doc: Doc | undefined, hits: Finding[]): void {
  hiddenJs(file, hits);
  patchSink(file, hits);
  devImport(file, doc, hits);
  rawSql(file, hits);
  mongo(file, hits);
  socket(file, hits);
  rewrite(file, hits);
  matcher(file, hits);
  framework(file, hits);
  fastify(file, hits);
  graphql(file, hits);
  listen(file, hits);
  bodyLimit(file, hits);
  debugRoute(file, hits);
}

function manifestChecks(file: Loaded, note: string | undefined, hits: Finding[]): void {
  hiddenUrl(file, hits);
  filesLeak(file, hits);
  ignoreLeak(file, hits);
  privateWorkspace(file, hits);
  installFetch(file, hits);
  binaryFetch(file, hits);
  loaderScript(file, hits);
  if (file.name === 'package.json') {nodeDrift(file.text, note, hits, file.rel);}
}

function disagree(left: Map<string, string>, right: Map<string, string>): string | undefined {
  for (const [name, version] of left) {
    const other = right.get(name);
    if (other !== undefined && other !== version) {return name;}
  }
  return undefined;
}

function lockPair(files: readonly Loaded[], hits: Finding[]): void {
  const npm = files.find((file) => file.name === 'package-lock.json');
  const yarn = files.find((file) => file.name === 'yarn.lock');
  const pnpm = files.find((file) => file.name === 'pnpm-lock.yaml');
  if (npm === undefined) {return;}
  const other = yarn ?? pnpm;
  if (other === undefined) {return;}
  const name = disagree(lockMap(npm.text), other.name === 'yarn.lock' ? yarnMap(other.text) : pnpmMap(other.text));
  add(hits, other.rel, other.text, name !== undefined, {
    n: '005', severity: 'low', title: 'Lockfiles disagree', message: `${name ?? ''} is a different version in the two lockfiles.`, needle: name ?? '',
  });
}

function typeSkew(files: readonly Loaded[], hits: Finding[]): void {
  const npm = files.find((file) => file.name === 'package-lock.json');
  if (npm === undefined) {return;}
  const versions = lockMap(npm.text);
  for (const [name, version] of versions) {
    if (!name.startsWith('@types/')) {continue;}
    const runtime = versions.get(name.slice('@types/'.length));
    if (runtime !== undefined && majorOf(version) !== majorOf(runtime)) {
      add(hits, npm.rel, npm.text, true, {
        n: '015', severity: 'low', title: 'Types package major skew', message: `${name} major does not match the runtime package.`, needle: name,
      });
      return;
    }
  }
}

function keep(fileName: string, rel: string): boolean {
  if (SOURCE_EXT.has(extname(fileName)) || LOCKS.has(fileName)) {return true;}
  if (fileName === 'package.json' || fileName === '.npmignore' || fileName === '.nvmrc' || fileName === '.node-version') {return true;}
  return rel.includes('patches/') || fileName.includes('config');
}

async function load(dir: string, cwd: string, out: Loaded[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {continue;}
    if (entry.isDirectory()) {
      if (!SKIP.has(entry.name)) {await load(join(dir, entry.name), cwd, out);}
      continue;
    }
    const abs = join(dir, entry.name);
    const rel = relative(cwd, abs);
    if (!keep(entry.name, rel)) {continue;}
    const text = await readFile(abs, 'utf8');
    if (text.length <= 200_000) {out.push({ rel, name: entry.name, text });}
  }
}

async function collect(cwd: string): Promise<Finding[]> {
  const files: Loaded[] = [];
  await load(cwd, cwd, files);
  const pkg = files.find((file) => file.rel === 'package.json');
  const doc = pkg === undefined ? undefined : parseDoc(pkg.text);
  const note = files.find((file) => file.name === '.nvmrc')?.text ?? files.find((file) => file.name === '.node-version')?.text;
  const hits: Finding[] = [];
  for (const file of files) {
    sourceChecks(file, doc, hits);
    manifestChecks(file, note, hits);
  }
  lockPair(files, hits);
  typeSkew(files, hits);
  return hits;
}

export async function withSectionH(result: ScanResult, cwd: string): Promise<ScanResult> {
  if (!on()) {return result;}
  return withExtraFindings(result, await collect(cwd));
}
