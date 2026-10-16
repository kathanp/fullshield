export type LockfileKind = 'npm' | 'yarn' | 'pnpm';

export function lockfileKind(filename: string): LockfileKind | undefined {
  const base = filename.replace(/\\/g, '/').split('/').pop() ?? filename;
  if (base === 'package-lock.json') return 'npm';
  if (base === 'yarn.lock') return 'yarn';
  if (base === 'pnpm-lock.yaml') return 'pnpm';
  return undefined;
}

export function collectManifestOverrides(manifestRaw: string): Map<string, string> {
  const out = new Map<string, string>();
  try {
    const pkg = JSON.parse(manifestRaw) as {
      overrides?: Record<string, unknown>;
      resolutions?: Record<string, unknown>;
      pnpm?: { overrides?: Record<string, unknown> };
    };
    const blocks = [pkg.overrides, pkg.resolutions, pkg.pnpm?.overrides];
    for (const block of blocks) {
      if (block === undefined || typeof block !== 'object' || Array.isArray(block)) continue;
      for (const [name, version] of Object.entries(block)) {
        if (typeof version === 'string' && version.length > 0) out.set(name, version);
      }
    }
  } catch {
    return out;
  }
  return out;
}

function stringMap(value: unknown): Record<string, string> {
  if (value === undefined || value === null || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'string') out[key] = entry;
  }
  return out;
}

function objectMap(value: unknown): Record<string, unknown> {
  if (value === undefined || value === null || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return { ...value };
}

export function withManifestOverride(
  manifestRaw: string,
  kind: LockfileKind,
  name: string,
  version: string,
): string {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(manifestRaw) as Record<string, unknown>;
  } catch {
    return manifestRaw;
  }
  if (kind === 'yarn') {
    pkg.resolutions = { ...stringMap(pkg.resolutions), [name]: version };
  } else if (kind === 'pnpm') {
    const pnpm = objectMap(pkg.pnpm);
    pnpm.overrides = { ...stringMap(pnpm.overrides), [name]: version };
    pkg.pnpm = pnpm;
  } else {
    pkg.overrides = { ...stringMap(pkg.overrides), [name]: version };
  }
  return `${JSON.stringify(pkg, null, 2)}\n`;
}
