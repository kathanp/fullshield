import { parseBunLock, parsePnpmV9, parseYarnBerry } from './lockfile-modern.js';

export interface LockedPackage {
  name: string;
  version: string;
  path: string;
  deprecated?: string;
}

function basename(filename: string): string {
  const parts = filename.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] ?? filename;
}

function dedupe(packages: LockedPackage[]): LockedPackage[] {
  const seen = new Set<string>();
  const out: LockedPackage[] = [];
  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(pkg);
  }
  return out;
}

function nameFromPackagesKey(key: string): string | undefined {
  if (key === '') return undefined;
  const idx = key.lastIndexOf('node_modules/');
  if (idx === -1) return undefined;
  const name = key.slice(idx + 'node_modules/'.length);
  return name.length > 0 ? name : undefined;
}

interface NpmPackageEntry {
  version?: unknown;
  deprecated?: unknown;
  dependencies?: unknown;
  optionalDependencies?: unknown;
  devDependencies?: unknown;
}

export interface LockfileGraph {
  packages: LockedPackage[];
  /** package name → names it depends on (union across nested copies). */
  edges: Map<string, Set<string>>;
  directProd: Set<string>;
  directDev: Set<string>;
  /**
   * False when this lockfile format has no parsed dependency links.
   * Callers must not treat missing paths as `not-imported`.
   */
  edgesKnown: boolean;
}

function objectKeys(value: unknown): string[] {
  if (value === undefined || value === null || typeof value !== 'object' || Array.isArray(value)) {
    return [];
  }
  return Object.keys(value);
}

function addEdge(edges: Map<string, Set<string>>, from: string, to: string): void {
  const set = edges.get(from) ?? new Set<string>();
  set.add(to);
  edges.set(from, set);
}

function fromPackagesTable(packages: Record<string, NpmPackageEntry>): LockedPackage[] {
  const out: LockedPackage[] = [];
  for (const [key, value] of Object.entries(packages)) {
    const name = nameFromPackagesKey(key);
    if (name === undefined || typeof value.version !== 'string') continue;
    out.push({
      name,
      version: value.version,
      path: key,
      deprecated: typeof value.deprecated === 'string' ? value.deprecated : undefined,
    });
  }
  return dedupe(out);
}

function fromDependenciesTree(
  deps: Record<string, NpmPackageEntry>,
  prefix: string,
): LockedPackage[] {
  const out: LockedPackage[] = [];
  for (const [name, value] of Object.entries(deps)) {
    if (typeof value.version !== 'string') continue;
    const path = prefix === '' ? `node_modules/${name}` : `${prefix}/node_modules/${name}`;
    out.push({
      name,
      version: value.version,
      path,
      deprecated: typeof value.deprecated === 'string' ? value.deprecated : undefined,
    });
    if (value.dependencies !== undefined && typeof value.dependencies === 'object' && value.dependencies !== null) {
      out.push(
        ...fromDependenciesTree(value.dependencies as Record<string, NpmPackageEntry>, path),
      );
    }
  }
  return dedupe(out);
}

function yarnNameFromKey(key: string): string | undefined {
  const first = key.split(',')[0]?.trim().replace(/^"|"$/g, '');
  if (first === undefined || first.length === 0) return undefined;
  if (first.startsWith('@')) {
    const match = /^(@[^@/]+\/[^@/]+)@/.exec(first);
    return match?.[1];
  }
  const at = first.indexOf('@');
  return at === -1 ? first : first.slice(0, at);
}

function parseYarnGraph(contents: string): Omit<LockfileGraph, 'directProd' | 'directDev'> & {
  directProd: Set<string>;
  directDev: Set<string>;
} {
  const packages: LockedPackage[] = [];
  const edges = new Map<string, Set<string>>();
  let currentName: string | undefined;
  let inDeps = false;
  for (const raw of contents.split(/\r?\n/)) {
    if (raw.startsWith('#')) continue;
    if (raw.trim() === '') {
      inDeps = false;
      continue;
    }
    if (!raw.startsWith(' ') && raw.trimEnd().endsWith(':')) {
      currentName = yarnNameFromKey(raw.slice(0, -1).trim());
      inDeps = false;
      continue;
    }
    const versionClassic = /^\s+version\s+"([^"]+)"/.exec(raw);
    const versionBerry = /^\s+version:\s+["']?([^"'\s]+)["']?/.exec(raw);
    const ver = versionClassic?.[1] ?? versionBerry?.[1];
    if (ver !== undefined && currentName !== undefined && !inDeps) {
      packages.push({ name: currentName, version: ver, path: `yarn:${currentName}` });
      continue;
    }
    if (/^\s+dependencies:\s*$/.test(raw)) {
      inDeps = true;
      continue;
    }
    if (inDeps && currentName !== undefined) {
      const depClassic = /^\s{4}(?:"([^"]+)"|(@?[^\s]+))\s+"[^"]+"/.exec(raw);
      const depBerry = /^\s{4}(?:"([^"]+)"|(@?[\w./-]+)):/.exec(raw);
      const depName = depClassic?.[1] ?? depClassic?.[2] ?? depBerry?.[1] ?? depBerry?.[2];
      if (depName !== undefined) {
        addEdge(edges, currentName, depName);
        continue;
      }
      if (/^\s{2}\S/.test(raw)) inDeps = false;
    }
  }
  return {
    packages: dedupe(packages),
    edges,
    directProd: new Set<string>(),
    directDev: new Set<string>(),
    edgesKnown: true,
  };
}

const PNPM_KEY =
  /^ {2}['"]?(?:\/)?(@?[^'"@\s/]+(?:\/[^'"@\s/]+)?)@([^'"(\s:]+)(?:\([^)]*\))?['"]?:\s*$/;

function pnpmNameFromKey(key: string): string | undefined {
  let k = key.trim().replace(/^['"]|['"]$/g, '').replace(/^\//, '');
  k = k.replace(/\([^)]*\)$/, '');
  if (k.startsWith('@')) {
    const match = /^(@[^@/]+\/[^@/]+)@/.exec(k);
    return match?.[1];
  }
  const at = k.indexOf('@');
  return at <= 0 ? k : k.slice(0, at);
}

function pnpmVersionFromKey(key: string): string | undefined {
  let k = key.trim().replace(/^['"]|['"]$/g, '').replace(/^\//, '');
  k = k.replace(/\([^)]*\)$/, '');
  if (k.startsWith('@')) {
    const match = /^@[^@/]+\/[^@/]+@([^(\s]+)/.exec(k);
    return match?.[1];
  }
  const at = k.indexOf('@');
  return at <= 0 ? undefined : k.slice(at + 1);
}

function parsePnpmGraph(contents: string): LockfileGraph {
  const packages: LockedPackage[] = [];
  const edges = new Map<string, Set<string>>();
  const directProd = new Set<string>();
  const directDev = new Set<string>();
  let section: 'none' | 'importers' | 'packages' = 'none';
  let importerField: 'prod' | 'dev' | undefined;
  let currentPkg: string | undefined;
  let inPkgDeps = false;

  for (const raw of contents.split(/\r?\n/)) {
    if (/^importers:\s*$/.test(raw)) {
      section = 'importers';
      continue;
    }
    if (/^packages:\s*$/.test(raw)) {
      section = 'packages';
      currentPkg = undefined;
      inPkgDeps = false;
      continue;
    }
    if (raw.length > 0 && !raw.startsWith(' ') && !raw.startsWith('\t')) {
      if (!/^importers:\s*$/.test(raw) && !/^packages:\s*$/.test(raw)) section = 'none';
      continue;
    }

    if (section === 'importers') {
      if (/^    dependencies:\s*$/.test(raw)) {
        importerField = 'prod';
        continue;
      }
      if (/^    devDependencies:\s*$/.test(raw)) {
        importerField = 'dev';
        continue;
      }
      const depName = /^      (?:'([^']+)'|"([^"]+)"|([^:]+)):/.exec(raw);
      const name = depName?.[1] ?? depName?.[2] ?? depName?.[3];
      if (name !== undefined && importerField !== undefined) {
        if (importerField === 'prod') directProd.add(name);
        else directDev.add(name);
      }
      continue;
    }

    if (section === 'packages') {
      const keyLine = /^ {2}['"]?(.+?)['"]?:\s*$/.exec(raw);
      if (keyLine?.[1] !== undefined && !raw.startsWith('    ')) {
        currentPkg = pnpmNameFromKey(keyLine[1]);
        const ver = pnpmVersionFromKey(keyLine[1]);
        if (currentPkg !== undefined && ver !== undefined) {
          packages.push({ name: currentPkg, version: ver, path: `pnpm:${currentPkg}` });
        }
        inPkgDeps = false;
        continue;
      }
      if (/^    dependencies:\s*$/.test(raw)) {
        inPkgDeps = true;
        continue;
      }
      if (inPkgDeps && currentPkg !== undefined) {
        const dep = /^      (?:'([^']+)'|"([^"]+)"|([^:]+)):/.exec(raw);
        const depName = dep?.[1] ?? dep?.[2] ?? dep?.[3];
        if (depName !== undefined) {
          addEdge(edges, currentPkg, depName);
          continue;
        }
        if (/^    \S/.test(raw)) inPkgDeps = false;
      }
    }
  }

  if (packages.length === 0) {
    for (const raw of contents.split(/\r?\n/)) {
      const match = PNPM_KEY.exec(raw);
      if (match?.[1] !== undefined && match[2] !== undefined) {
        packages.push({ name: match[1], version: match[2], path: `pnpm:${match[1]}` });
      }
    }
  }

  return {
    packages: dedupe(packages),
    edges,
    directProd,
    directDev,
    edgesKnown: true,
  };
}

/** Parse an npm / yarn / pnpm lockfile into `{name, version, path}` entries. */
export function parseLockfile(filename: string, contents: string): LockedPackage[] {
  return parseLockfileGraph(filename, contents).packages;
}

function graphFromPackagesTable(packages: Record<string, NpmPackageEntry>): Pick<
  LockfileGraph,
  'edges' | 'directProd' | 'directDev'
> {
  const edges = new Map<string, Set<string>>();
  const root = packages[''] ?? {};
  const directProd = new Set(objectKeys(root.dependencies));
  const directDev = new Set(objectKeys(root.devDependencies));
  for (const [key, value] of Object.entries(packages)) {
    const name = key === '' ? '' : nameFromPackagesKey(key);
    if (name === undefined || name.length === 0) continue;
    for (const dep of [...objectKeys(value.dependencies), ...objectKeys(value.optionalDependencies)]) {
      addEdge(edges, name, dep);
    }
  }
  return { edges, directProd, directDev };
}

function graphFromDependenciesTree(
  deps: Record<string, NpmPackageEntry>,
  edges: Map<string, Set<string>>,
): void {
  for (const [name, value] of Object.entries(deps)) {
    const child = value.dependencies;
    if (child === undefined || typeof child !== 'object' || child === null) continue;
    const nested = child as Record<string, NpmPackageEntry>;
    for (const childName of Object.keys(nested)) addEdge(edges, name, childName);
    graphFromDependenciesTree(nested, edges);
  }
}

/** Packages plus the dependency graph. Yarn/pnpm include real edges when listed. */
export function parseLockfileGraph(filename: string, contents: string): LockfileGraph {
  const name = basename(filename);
  const empty: LockfileGraph = {
    packages: [],
    edges: new Map(),
    directProd: new Set(),
    directDev: new Set(),
    edgesKnown: false,
  };
  const modern = process.env.FULLSHIELD_EXPERIMENTAL_LOCKFILES === '1';
  if (name === 'yarn.lock') {
    if (modern && contents.includes('__metadata')) return parseYarnBerry(contents);
    return parseYarnGraph(contents);
  }
  if (name === 'pnpm-lock.yaml') {
    if (modern && /lockfileVersion:\s*['"]?9/.test(contents)) return parsePnpmV9(contents);
    return parsePnpmGraph(contents);
  }
  if (modern && name === 'bun.lock') return parseBunLock(contents);
  if (name !== 'package-lock.json') return empty;

  try {
    const json = JSON.parse(contents) as {
      packages?: Record<string, NpmPackageEntry>;
      dependencies?: Record<string, NpmPackageEntry>;
    };
    if (json.packages !== undefined && typeof json.packages === 'object') {
      const meta = graphFromPackagesTable(json.packages);
      return { packages: fromPackagesTable(json.packages), ...meta, edgesKnown: true };
    }
    if (json.dependencies !== undefined && typeof json.dependencies === 'object') {
      const edges = new Map<string, Set<string>>();
      graphFromDependenciesTree(json.dependencies, edges);
      return {
        packages: fromDependenciesTree(json.dependencies, ''),
        edges,
        directProd: new Set(Object.keys(json.dependencies)),
        directDev: new Set<string>(),
        edgesKnown: true,
      };
    }
  } catch {
    return empty;
  }
  return empty;
}
