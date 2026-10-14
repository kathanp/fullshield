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

function parseYarnLock(contents: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  let currentKey: string | undefined;
  for (const raw of contents.split(/\r?\n/)) {
    if (raw.startsWith('#') || raw.trim() === '') continue;
    if (!raw.startsWith(' ') && raw.endsWith(':')) {
      currentKey = raw.slice(0, -1).trim();
      continue;
    }
    const versionMatch = /^\s+version\s+"([^"]+)"/.exec(raw);
    if (versionMatch?.[1] !== undefined && currentKey !== undefined) {
      const name = yarnNameFromKey(currentKey);
      if (name !== undefined) {
        out.push({ name, version: versionMatch[1], path: `yarn:${name}` });
      }
      currentKey = undefined;
    }
  }
  return dedupe(out);
}

const PNPM_KEY =
  /^ {2}['"]?(?:\/)?(@?[^'"@\s/]+(?:\/[^'"@\s/]+)?)@([^'"(\s:]+)(?:\([^)]*\))?['"]?:\s*$/;

function parsePnpmLock(contents: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  let inPackages = false;
  for (const raw of contents.split(/\r?\n/)) {
    if (/^packages:\s*$/.test(raw)) {
      inPackages = true;
      continue;
    }
    if (inPackages && raw.length > 0 && !raw.startsWith(' ') && !raw.startsWith('\t')) {
      inPackages = /^packages:\s*$/.test(raw);
      continue;
    }
    if (!inPackages) continue;
    const match = PNPM_KEY.exec(raw);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      out.push({ name: match[1], version: match[2], path: `pnpm:${match[1]}` });
    }
  }
  return dedupe(out);
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

/** Packages plus the dependency graph (npm lockfiles). Yarn/pnpm have no edges. */
export function parseLockfileGraph(filename: string, contents: string): LockfileGraph {
  const name = basename(filename);
  const empty = {
    packages: [] as LockedPackage[],
    edges: new Map<string, Set<string>>(),
    directProd: new Set<string>(),
    directDev: new Set<string>(),
  };
  if (name === 'yarn.lock') return { ...empty, packages: parseYarnLock(contents) };
  if (name === 'pnpm-lock.yaml') return { ...empty, packages: parsePnpmLock(contents) };
  if (name !== 'package-lock.json') return empty;

  try {
    const json = JSON.parse(contents) as {
      packages?: Record<string, NpmPackageEntry>;
      dependencies?: Record<string, NpmPackageEntry>;
    };
    if (json.packages !== undefined && typeof json.packages === 'object') {
      const meta = graphFromPackagesTable(json.packages);
      return { packages: fromPackagesTable(json.packages), ...meta };
    }
    if (json.dependencies !== undefined && typeof json.dependencies === 'object') {
      const edges = new Map<string, Set<string>>();
      graphFromDependenciesTree(json.dependencies, edges);
      return {
        packages: fromDependenciesTree(json.dependencies, ''),
        edges,
        directProd: new Set(Object.keys(json.dependencies)),
        directDev: new Set<string>(),
      };
    }
  } catch {
    return empty;
  }
  return empty;
}
