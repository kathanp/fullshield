import type { LockedPackage, LockfileGraph } from './lockfile.js';

function addEdge(edges: Map<string, Set<string>>, from: string, to: string): void {
  if (from.length === 0 || to.length === 0 || from === to) {return;}
  const list = edges.get(from) ?? new Set<string>();
  list.add(to);
  edges.set(from, list);
}

function graph(packages: LockedPackage[], edges: Map<string, Set<string>>, directProd: Set<string>, directDev: Set<string>, edgesKnown: boolean): LockfileGraph {
  return { packages, edges, directProd, directDev, edgesKnown };
}

/** Yarn Berry lockfiles start with a `__metadata` block. `npm:` and `patch:` resolve to the underlying version. */
export function parseYarnBerry(contents: string): LockfileGraph {
  const packages: LockedPackage[] = [];
  const edges = new Map<string, Set<string>>();
  const directProd = new Set<string>();
  const directDev = new Set<string>();
  let current: string | undefined;
  let inDeps = false;
  let devBlock = false;
  for (const raw of contents.split(/\r?\n/)) {
    if (!raw.startsWith(' ') && raw.trimEnd().endsWith(':')) {
      const key = raw.slice(0, -1).trim().replace(/^"|"$/g, '');
      current = key.includes('@workspace:.') ? '' : nameFromBerryKey(key);
      inDeps = false;
      devBlock = false;
      continue;
    }
    const version = /^\s+version:\s+(.+)$/.exec(raw)?.[1]?.replace(/["']/g, '').trim();
    if (version !== undefined && current !== undefined && current.length > 0 && !inDeps) {
      packages.push({ name: current, version: versionFromProtocol(version), path: `yarn:${current}` });
      continue;
    }
    if (/^\s+dependencies:\s*$/.test(raw)) {
      inDeps = true;
      devBlock = false;
      continue;
    }
    if (/^\s+devDependencies:\s*$/.test(raw)) {
      inDeps = true;
      devBlock = true;
      continue;
    }
    if (!inDeps || current === undefined) {continue;}
    const dep = /^\s{4}"?([^":]+)"?:\s+(.+)$/.exec(raw);
    if (dep?.[1] === undefined) {continue;}
    const depName = dep[1];
    if (current.length === 0) {
      if (devBlock) {directDev.add(depName);}
      else {directProd.add(depName);}
    } else {
      addEdge(edges, current, depName);
    }
  }
  return graph(packages, edges, directProd, directDev, true);
}

function nameFromBerryKey(key: string): string | undefined {
  const first = key.split(',')[0]?.trim() ?? key;
  if (first.startsWith('@')) {
    const match = /^(@[^@/]+\/[^@/]+)@/.exec(first);
    return match?.[1];
  }
  const at = first.indexOf('@');
  return at <= 0 ? first : first.slice(0, at);
}

function versionFromProtocol(raw: string): string {
  const patch = /^patch:(.+)#/.exec(raw);
  const body = patch?.[1] ?? raw;
  const npm = /^(?:npm:)?(@?[^@]+)@(.+)$/.exec(body);
  if (npm?.[2] !== undefined) {return npm[2];}
  return body;
}

/** pnpm lockfile v9 splits importers, packages, and snapshots. */
export function parsePnpmV9(contents: string): LockfileGraph {
  const packages: LockedPackage[] = [];
  const edges = new Map<string, Set<string>>();
  const directProd = new Set<string>();
  const directDev = new Set<string>();
  type Block = 'none' | 'importer-deps' | 'importer-dev' | 'packages' | 'snapshots';
  let block: Block = 'none';
  let snapshot: string | undefined;
  let inSnapshotDeps = false;
  for (const raw of contents.split(/\r?\n/)) {
    if (raw === 'packages:') {
      block = 'packages';
      snapshot = undefined;
      continue;
    }
    if (raw === 'snapshots:') {
      block = 'snapshots';
      snapshot = undefined;
      continue;
    }
    if (raw === 'importers:' || raw.startsWith('lockfileVersion:')) {
      block = 'none';
      continue;
    }
    if (block !== 'snapshots' && /^\s{4}dependencies:\s*$/.test(raw)) {
      block = 'importer-deps';
      continue;
    }
    if (/^\s{4}devDependencies:\s*$/.test(raw)) {
      block = 'importer-dev';
      continue;
    }
    if (block === 'packages') {
      const header = /^\s{2}['"]?(@?[^@'\s]+)@([^:'"]+)['"]?:/.exec(raw);
      if (header?.[1] !== undefined && header[2] !== undefined) {
        packages.push({ name: header[1], version: header[2], path: `pnpm:${header[1]}` });
      }
      continue;
    }
    if (block === 'snapshots') {
      const header = /^\s{2}['"]?(@?[^@'\s]+)@([^:'"]+)['"]?:/.exec(raw);
      if (header?.[1] !== undefined) {
        snapshot = header[1];
        inSnapshotDeps = false;
        continue;
      }
      if (/^\s+dependencies:\s*$/.test(raw)) {
        inSnapshotDeps = true;
        continue;
      }
      if (inSnapshotDeps && snapshot !== undefined) {
        const dep = /^\s{6}['"]?([^'":]+)['"]?:/.exec(raw);
        if (dep?.[1] !== undefined) {addEdge(edges, snapshot, dep[1]);}
      }
      continue;
    }
    if (block === 'importer-deps' || block === 'importer-dev') {
      const dep = /^\s{6}['"]?([^'":]+)['"]?:/.exec(raw);
      if (dep?.[1] !== undefined && !raw.trim().startsWith('specifier') && !raw.trim().startsWith('version')) {
        if (block === 'importer-dev') {directDev.add(dep[1]);}
        else {directProd.add(dep[1]);}
      }
    }
  }
  return graph(packages, edges, directProd, directDev, true);
}

/** Bun text lockfile. Comments are stripped. The binary bun.lockb is not parsed here. */
export function parseBunLock(contents: string): LockfileGraph {
  const stripped = contents.replace(/^\s*\/\/.*$/gm, '');
  const packages: LockedPackage[] = [];
  const edges = new Map<string, Set<string>>();
  const directProd = new Set<string>();
  const directDev = new Set<string>();
  try {
    const json = JSON.parse(stripped) as {
      packages?: Record<string, unknown>;
    };
    for (const [name, value] of Object.entries(json.packages ?? {})) {
      if (!Array.isArray(value)) {continue;}
      const entry: unknown[] = Array.from(value as unknown[]);
      const spec = typeof entry[0] === 'string' ? entry[0] : '';
      const version = spec.includes('@') ? spec.slice(spec.lastIndexOf('@') + 1) : spec;
      packages.push({ name, version, path: `bun:${name}` });
      const meta = entry[1];
      if (meta !== null && typeof meta === 'object' && 'dependencies' in meta) {
        const deps = meta.dependencies;
        if (deps !== null && typeof deps === 'object') {
          for (const dep of Object.keys(deps)) {addEdge(edges, name, dep);}
        }
      }
    }
  } catch {
    return graph([], new Map(), new Set(), new Set(), false);
  }
  return graph(packages, edges, directProd, directDev, packages.length > 0);
}
