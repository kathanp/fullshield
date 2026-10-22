import { readFile } from 'node:fs/promises';
import { AsyncLocalStorage } from 'node:async_hooks';
import { join } from 'node:path';

import { assertRegistryUrl } from '../../../supply/index.js';
import { NPM_GROUPS } from './groups.js';
import { npmFlag, type NpmDepthInput, type NpmFacts, type NpmGraphNode, type NpmLockRow } from './types.js';

const factsStore = new AsyncLocalStorage<NpmFacts>();

/** Facts for the scan currently running inside `runWithFacts`. */
export function currentFacts(): NpmFacts | undefined {
  return factsStore.getStore();
}

export function runWithFacts<T>(facts: NpmFacts, fn: () => Promise<T>): Promise<T> {
  return factsStore.run(facts, fn);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
  return value as Record<string, unknown>;
}

function nameFromKey(path: string): string | undefined {
  const mark = 'node_modules/';
  const idx = path.lastIndexOf(mark);
  if (idx === -1) {return undefined;}
  const name = path.slice(idx + mark.length);
  return name.length > 0 ? name : undefined;
}

function stringKeys(value: unknown): string[] {
  const rec = asRecord(value);
  return rec === undefined ? [] : Object.keys(rec);
}

function parseManifest(raw: string | undefined): Record<string, unknown> | undefined {
  if (raw === undefined) {return undefined;}
  try {
    return asRecord(JSON.parse(raw) as unknown);
  } catch {
    return undefined;
  }
}

function lockRowsFrom(lockTexts: Readonly<Record<string, string>>): NpmLockRow[] {
  const rows: NpmLockRow[] = [];
  for (const text of Object.values(lockTexts)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      continue;
    }
    const packages = asRecord(asRecord(parsed)?.packages);
    if (packages === undefined) {continue;}
    for (const [path, value] of Object.entries(packages)) {
      const rec = asRecord(value);
      if (rec === undefined) {continue;}
      const named = path === '' ? (typeof rec.name === 'string' ? rec.name : undefined) : nameFromKey(path);
      rows.push({
        path,
        name: named,
        version: typeof rec.version === 'string' ? rec.version : undefined,
        resolved: typeof rec.resolved === 'string' ? rec.resolved : undefined,
        integrity: typeof rec.integrity === 'string' ? rec.integrity : undefined,
        deps: stringKeys(rec.dependencies),
      });
    }
  }
  return rows;
}

function graphFrom(rows: readonly NpmLockRow[]): NpmGraphNode[] {
  const out: NpmGraphNode[] = [];
  for (const row of rows) {
    if (row.name === undefined || row.path === '') {continue;}
    out.push({ path: row.path, name: row.name, version: row.version, deps: row.deps });
  }
  return out;
}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as unknown;
  } catch {
    return undefined;
  }
}

async function readFirst(paths: readonly string[]): Promise<unknown> {
  for (const path of paths) {
    const raw = await readJson(path);
    if (raw !== undefined) {return raw;}
  }
  return undefined;
}

function registryPaths(cacheDir: string, name: string): string[] {
  return [
    join(cacheDir, 'registry', `${name.replaceAll('/', '__')}.json`),
    join(cacheDir, 'registry', `${name}.json`),
    join(cacheDir, 'registry', `${encodeURIComponent(name)}.json`),
  ];
}

function tarballPaths(cacheDir: string, name: string): string[] {
  return [
    join(cacheDir, 'tarballs', `${encodeURIComponent(name)}.json`),
    join(cacheDir, 'tarballs', `${name}.json`),
    join(cacheDir, 'tarballs', `${name.replaceAll('/', '%2f')}.json`),
  ];
}

function integrityFile(integrity: string): string {
  return `${integrity.replaceAll('/', '_').replaceAll('+', '_')}.tar`;
}

const REGISTRY_HOST = 'registry.npmjs.org';

function isRegistryTarball(url: string | undefined): url is string {
  if (url === undefined) {return false;}
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' && parsed.hostname === REGISTRY_HOST;
  } catch {
    return false;
  }
}

function packumentUrl(name: string): string {
  return `https://${REGISTRY_HOST}/${encodeURIComponent(name)}`;
}

function wantsPackument(): boolean {
  const flags = [
    ...NPM_GROUPS.NPM_REGISTRY,
    ...NPM_GROUPS.NPM_TARBALL,
    'NPM_SCOPE_NEW',
    'NPM_TYPES',
    'NPM_DUALPACKAGE',
  ];
  return flags.some((flag) => npmFlag(flag));
}

function wantsTarball(): boolean {
  return NPM_GROUPS.NPM_TARBALL.some((flag) => npmFlag(flag))
    || NPM_GROUPS.NPM_SCRIPTS.some((flag) => npmFlag(flag));
}

function rememberScripts(into: Map<string, string>, source: string, value: unknown): void {
  const scripts = asRecord(asRecord(value)?.scripts) ?? asRecord(asRecord(asRecord(value)?.packument)?.scripts);
  if (scripts === undefined) {return;}
  for (const [key, body] of Object.entries(scripts)) {
    if (typeof body === 'string') {into.set(`${source}:${key}`, body);}
  }
}

/**
 * Read lock rows, the manifest, `.npmrc`, packuments, tarballs, script text,
 * names, and the lock graph once. Network reads go through `input.fetchImpl`
 * and each packument name and each tarball URL is requested at most once.
 */
export async function loadNpmFacts(input: NpmDepthInput): Promise<NpmFacts> {
  const manifest = parseManifest(input.manifestRaw);
  const lockRows = lockRowsFrom(input.lockTexts);
  const graph = graphFrom(lockRows);
  const names = [...new Set(lockRows.flatMap((row) => (row.name === undefined ? [] : [row.name])))].sort();
  const npmrcFiles = new Map<string, string>();
  for (const file of input.files) {
    const norm = file.replaceAll('\\', '/');
    if (norm === 'home/.npmrc' || (norm !== '.npmrc' && !norm.endsWith('/.npmrc'))) {continue;}
    try {
      npmrcFiles.set(norm, await readFile(join(input.cwd, file), 'utf8'));
    } catch {
      // unreadable project npmrc is not a fact
    }
  }
  let homeNpmrc: string | undefined;
  const home = process.env.FULLSHIELD_NPM_HOME;
  if (home !== undefined && home.trim() !== '') {
    try {
      homeNpmrc = await readFile(join(home, '.npmrc'), 'utf8');
    } catch {
      homeNpmrc = undefined;
    }
  }

  const packuments = new Map<string, unknown>();
  const tarballs = new Map<string, unknown>();
  const tarballBytes = new Map<string, Buffer>();
  const scriptText = new Map<string, string>();
  rememberScripts(scriptText, 'package.json', manifest);

  const packageNames = new Set(names);
  if (manifest !== undefined) {
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const name of stringKeys(manifest[field])) {packageNames.add(name);}
    }
  }

  for (const name of packageNames) {
    const raw = await readFirst(registryPaths(input.cacheDir, name));
    if (raw !== undefined) {packuments.set(name, raw);}
    const tar = await readFirst(tarballPaths(input.cacheDir, name));
    if (tar !== undefined) {
      tarballs.set(name, tar);
      rememberScripts(scriptText, name, tar);
    }
  }
  for (const row of lockRows) {
    if (row.integrity === undefined) {continue;}
    if (tarballBytes.has(row.integrity)) {continue;}
    try {
      tarballBytes.set(row.integrity, await readFile(join(input.cacheDir, 'tarballs', integrityFile(row.integrity))));
    } catch {
      // missing integrity file stays a cache miss
    }
  }

  const fetchImpl = input.fetchImpl;
  if (fetchImpl !== undefined && !input.offline) {
    const seenPack = new Set<string>();
    const seenTar = new Set<string>();
    if (wantsPackument()) {
      for (const name of packageNames) {
        if (packuments.has(name) || seenPack.has(name)) {continue;}
        seenPack.add(name);
        const url = packumentUrl(name);
        assertRegistryUrl(url);
        const response = await fetchImpl(url);
        if (!response.ok) {continue;}
        try {
          packuments.set(name, JSON.parse(Buffer.from(await response.arrayBuffer()).toString('utf8')) as unknown);
        } catch {
          // a body that is not JSON is a miss, not a second fetch
        }
      }
    }
    if (wantsTarball()) {
      for (const row of lockRows) {
        if (!isRegistryTarball(row.resolved) || seenTar.has(row.resolved)) {continue;}
        if (row.integrity !== undefined && tarballBytes.has(row.integrity)) {continue;}
        seenTar.add(row.resolved);
        assertRegistryUrl(row.resolved);
        const response = await fetchImpl(row.resolved);
        if (!response.ok) {continue;}
        const bytes = Buffer.from(await response.arrayBuffer());
        tarballBytes.set(row.resolved, bytes);
        if (row.integrity !== undefined) {tarballBytes.set(row.integrity, bytes);}
      }
    }
  }

  return {
    cwd: input.cwd,
    files: input.files,
    manifestRaw: input.manifestRaw,
    lockTexts: input.lockTexts,
    cacheDir: input.cacheDir,
    offline: input.offline,
    manifest,
    npmrcFiles,
    homeNpmrc,
    lockRows,
    names,
    graph,
    scriptText,
    packuments,
    tarballs,
    tarballBytes,
  };
}
