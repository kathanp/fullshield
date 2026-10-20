export interface LockedCapPackage {
  name: string;
  version: string;
  rel: string;
  integrity?: string;
  deps: string[];
}

interface NpmEntry {
  version?: unknown;
  integrity?: unknown;
  dependencies?: unknown;
  optionalDependencies?: unknown;
  devDependencies?: unknown;
}

function keys(value: unknown): string[] {
  if (value === undefined || value === null || typeof value !== 'object' || Array.isArray(value)) {return [];}
  return Object.keys(value);
}

function nameFromKey(key: string): string | undefined {
  if (key === '') {return undefined;}
  const idx = key.lastIndexOf('node_modules/');
  if (idx < 0) {return undefined;}
  const name = key.slice(idx + 'node_modules/'.length);
  return name.length > 0 ? name : undefined;
}

function rowFrom(key: string, value: NpmEntry): LockedCapPackage | undefined {
  const name = nameFromKey(key);
  if (name === undefined || typeof value.version !== 'string') {return undefined;}
  const row: LockedCapPackage = {
    name,
    version: value.version,
    rel: key,
    deps: [...new Set([...keys(value.dependencies), ...keys(value.optionalDependencies)])].sort(),
  };
  if (typeof value.integrity === 'string' && value.integrity.length > 0) {row.integrity = value.integrity;}
  return row;
}

/** npm package-lock.json packages table, including integrity for the capability cache. */
export function readLockPackages(text: string): { packages: LockedCapPackage[]; direct: string[] } | undefined {
  let json: { packages?: Record<string, NpmEntry> };
  try {
    json = JSON.parse(text) as { packages?: Record<string, NpmEntry> };
  } catch {
    return undefined;
  }
  if (json.packages === undefined || typeof json.packages !== 'object') {return undefined;}
  const root = json.packages[''] ?? {};
  const direct = [...new Set([...keys(root.dependencies), ...keys(root.devDependencies)])].sort();
  const byName = new Map<string, LockedCapPackage>();
  for (const [key, value] of Object.entries(json.packages)) {
    const row = rowFrom(key, value);
    if (row === undefined) {continue;}
    const prev = byName.get(row.name);
    if (prev === undefined || key.length < prev.rel.length) {byName.set(row.name, row);}
  }
  const packages = [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
  return { packages, direct };
}
