import type { LockedPackage } from './lockfile.js';

const MANIFEST_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

/** True for a spec that names one concrete published version (no range). */
export function isExactNpmVersion(spec: string): boolean {
  const trimmed = spec.trim();
  const bare = trimmed.startsWith('=') ? trimmed.slice(1).trim() : trimmed;
  if (bare.length === 0) return false;
  if (/^(workspace:|file:|http:|https:|git:|git\+|npm:|latest|next|\*)/i.test(bare)) return false;
  if (/[~^><*xX|]/.test(bare)) return false;
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(bare);
}

const MANIFEST_DEP_FIELDS = /"(dependencies|devDependencies|optionalDependencies)"\s*:/;

/** 1-based line of `"name":` inside a dependencies block, or undefined. */
export function lineOfManifestDep(raw: string, name: string): number | undefined {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const depLine = new RegExp(`^\\s*"${escaped}"\\s*:`);
  let inBlock = false;
  let depth = 0;
  const lines = raw.split(/\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const startsBlock = MANIFEST_DEP_FIELDS.test(line);
    if (startsBlock) {
      inBlock = true;
      depth = 0;
    }
    if (!inBlock) continue;
    for (const ch of line) {
      if (ch === '{') depth += 1;
      if (ch === '}') depth -= 1;
    }
    if (depLine.test(line) && depth >= 1) return i + 1;
    if (depth <= 0 && !startsBlock) inBlock = false;
  }
  return undefined;
}

export function exactPinsFromManifest(pkg: Record<string, unknown>): LockedPackage[] {
  const out: LockedPackage[] = [];
  for (const field of MANIFEST_FIELDS) {
    const block = pkg[field];
    if (block === null || typeof block !== 'object' || Array.isArray(block)) continue;
    for (const [name, spec] of Object.entries(block as Record<string, unknown>)) {
      if (typeof spec !== 'string' || !isExactNpmVersion(spec)) continue;
      const version = spec.trim().startsWith('=') ? spec.trim().slice(1).trim() : spec.trim();
      out.push({ name, version, path: `package.json:${field}` });
    }
  }
  return out;
}
