/** Shared import resolver for symbol reachability and taint v2. */

export interface ResolvedSpec {
  packageName?: string;
  subpath?: string;
  aliasTarget?: string;
}

/** npm package name plus an optional subpath (`lodash/merge`, `@scope/pkg/path`). */
export function packageSpec(spec: string): { packageName: string; subpath?: string } | undefined {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) return undefined;
  if (spec.startsWith('@')) {
    const parts = spec.split('/');
    if (parts.length < 2 || parts[0] === undefined || parts[1] === undefined) return undefined;
    const packageName = `${parts[0]}/${parts[1]}`;
    const rest = parts.slice(2).join('/');
    return rest.length > 0 ? { packageName, subpath: rest } : { packageName };
  }
  const [name, ...rest] = spec.split('/');
  if (name === undefined || name.length === 0) return undefined;
  const subpath = rest.join('/');
  return subpath.length > 0 ? { packageName: name, subpath } : { packageName: name };
}

/**
 * Apply the first matching tsconfig `paths` pattern. `*` is one path segment
 * run. No match returns the original spec.
 */
export function applyTsPaths(spec: string, paths: Readonly<Record<string, readonly string[]>>): string {
  for (const [pattern, targets] of Object.entries(paths)) {
    const target = targets[0];
    if (target === undefined) continue;
    if (pattern.includes('*')) {
      const [prefix, suffix] = pattern.split('*');
      if (prefix === undefined || suffix === undefined) continue;
      if (spec.startsWith(prefix) && spec.endsWith(suffix)) {
        const mid = spec.slice(prefix.length, spec.length - suffix.length);
        return target.replace('*', mid);
      }
      continue;
    }
    if (spec === pattern) return target;
  }
  return spec;
}

/** Package `exports` map. Only string targets are used; conditions are not guessed. */
export function applyPackageExports(
  subpath: string,
  exportsMap: Readonly<Record<string, string>>,
): string | undefined {
  const key = subpath.startsWith('.') ? subpath : `./${subpath}`;
  const target = exportsMap[key];
  return typeof target === 'string' ? target : undefined;
}
