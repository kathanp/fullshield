import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { parseLockfileGraph, type LockfileGraph } from '../modules/deps/lockfile.js';
import { exactPinsFromManifest } from '../modules/deps/pins.js';
import { licenseText } from './spdx-license.js';

const LOCKFILE_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

export interface SpdxComponent {
  role: 'root' | 'package';
  name: string;
  version: string;
  license?: string;
  downloadLocation?: string;
}

export interface SpdxPair {
  from: string;
  to: string;
}

export interface SpdxProject {
  name: string;
  version: string;
  components: SpdxComponent[];
  dependsOn: SpdxPair[];
}

interface Manifest {
  name: string;
  version: string;
  license?: unknown;
  raw: Record<string, unknown>;
}

interface LockMeta {
  license?: string;
  resolved?: string;
}

export function componentKey(component: SpdxComponent): string {
  return `${component.role}:${component.name}@${component.version}`;
}

export async function loadSpdxProject(cwd: string): Promise<SpdxProject> {
  const manifest = await readManifest(cwd);
  const lock = await readLockfile(cwd);
  if (lock === undefined) {return projectFromPins(cwd, manifest);}
  const graph = parseLockfileGraph(lock.name, lock.text);
  const meta = lock.name === 'package-lock.json' ? npmMeta(lock.text) : new Map<string, LockMeta>();
  const components = await componentsFromGraph(cwd, manifest, graph, meta);
  return {
    name: manifest.name,
    version: manifest.version,
    components,
    dependsOn: dependencyPairs(graph, components),
  };
}

async function readManifest(cwd: string): Promise<Manifest> {
  try {
    const raw = JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8')) as Record<string, unknown>;
    return {
      name: typeof raw.name === 'string' && raw.name.length > 0 ? raw.name : 'app',
      version: typeof raw.version === 'string' && raw.version.length > 0 ? raw.version : '0.0.0',
      license: raw.license,
      raw,
    };
  } catch {
    return { name: 'app', version: '0.0.0', raw: {} };
  }
}

async function readLockfile(cwd: string): Promise<{ name: string; text: string } | undefined> {
  for (const name of LOCKFILE_NAMES) {
    try {
      return { name, text: await readFile(join(cwd, name), 'utf8') };
    } catch {
      // try the next lockfile name
    }
  }
  return undefined;
}

function npmMeta(contents: string): Map<string, LockMeta> {
  const out = new Map<string, LockMeta>();
  let json: { packages?: Record<string, { license?: unknown; resolved?: unknown }> };
  try {
    json = JSON.parse(contents) as typeof json;
  } catch {
    return out;
  }
  const packages = json.packages;
  if (packages === undefined) {return out;}
  for (const [path, value] of Object.entries(packages)) {
    const license = licenseText(value.license);
    const resolved = typeof value.resolved === 'string' && value.resolved.length > 0 ? value.resolved : undefined;
    if (license !== undefined || resolved !== undefined) {out.set(path, { license, resolved });}
  }
  return out;
}

async function installedLicense(cwd: string, name: string, version: string): Promise<string | undefined> {
  try {
    const raw = JSON.parse(await readFile(join(cwd, 'node_modules', ...name.split('/'), 'package.json'), 'utf8')) as {
      version?: unknown;
      license?: unknown;
    };
    if (raw.version !== version) {return undefined;}
    return licenseText(raw.license);
  } catch {
    return undefined;
  }
}

async function componentsFromGraph(
  cwd: string,
  manifest: Manifest,
  graph: LockfileGraph,
  meta: Map<string, LockMeta>,
): Promise<SpdxComponent[]> {
  const components: SpdxComponent[] = [
    {
      role: 'root',
      name: manifest.name,
      version: manifest.version,
      license: licenseText(manifest.license) ?? meta.get('')?.license,
    },
  ];
  for (const pkg of graph.packages) {
    const extra = meta.get(pkg.path);
    const license = extra?.license ?? (await installedLicense(cwd, pkg.name, pkg.version));
    components.push({
      role: 'package',
      name: pkg.name,
      version: pkg.version,
      license,
      downloadLocation: extra?.resolved,
    });
  }
  return components;
}

async function projectFromPins(cwd: string, manifest: Manifest): Promise<SpdxProject> {
  const components: SpdxComponent[] = [
    { role: 'root', name: manifest.name, version: manifest.version, license: licenseText(manifest.license) },
  ];
  for (const pin of exactPinsFromManifest(manifest.raw)) {
    components.push({
      role: 'package',
      name: pin.name,
      version: pin.version,
      license: await installedLicense(cwd, pin.name, pin.version),
    });
  }
  return { name: manifest.name, version: manifest.version, components, dependsOn: [] };
}

function dependencyPairs(graph: LockfileGraph, components: SpdxComponent[]): SpdxPair[] {
  if (!graph.edgesKnown) {return [];}
  const root = components.find((component) => component.role === 'root');
  if (root === undefined) {return [];}
  const byName = packagesByName(components);
  return dedupePairs([...directPairs(root, graph, byName), ...edgePairs(graph, byName)]);
}

function packagesByName(components: SpdxComponent[]): Map<string, SpdxComponent[]> {
  const byName = new Map<string, SpdxComponent[]>();
  for (const component of components) {
    if (component.role !== 'package') {continue;}
    const list = byName.get(component.name) ?? [];
    list.push(component);
    byName.set(component.name, list);
  }
  return byName;
}

function directPairs(root: SpdxComponent, graph: LockfileGraph, byName: Map<string, SpdxComponent[]>): SpdxPair[] {
  const pairs: SpdxPair[] = [];
  const names = [...graph.directProd, ...graph.directDev].sort();
  for (const name of names) {
    for (const target of byName.get(name) ?? []) {
      pairs.push({ from: componentKey(root), to: componentKey(target) });
    }
  }
  return pairs;
}

function edgePairs(graph: LockfileGraph, byName: Map<string, SpdxComponent[]>): SpdxPair[] {
  const pairs: SpdxPair[] = [];
  for (const sourceName of [...graph.edges.keys()].sort()) {
    const targets = [...(graph.edges.get(sourceName) ?? [])].sort();
    for (const source of byName.get(sourceName) ?? []) {appendEdges(pairs, source, targets, byName);}
  }
  return pairs;
}

function appendEdges(
  pairs: SpdxPair[],
  source: SpdxComponent,
  targetNames: string[],
  byName: Map<string, SpdxComponent[]>,
): void {
  const from = componentKey(source);
  for (const targetName of targetNames) {
    for (const target of byName.get(targetName) ?? []) {
      const to = componentKey(target);
      if (from === to) {continue;}
      pairs.push({ from, to });
    }
  }
}

function dedupePairs(pairs: SpdxPair[]): SpdxPair[] {
  const seen = new Set<string>();
  const out: SpdxPair[] = [];
  for (const pair of pairs) {
    const id = `${pair.from}|${pair.to}`;
    if (seen.has(id)) {continue;}
    seen.add(id);
    out.push(pair);
  }
  return out;
}
