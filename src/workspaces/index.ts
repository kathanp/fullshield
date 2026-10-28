import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

function workspacePatterns(dir: string): string[] {
  const manifestPath = join(dir, 'package.json');
  if (!existsSync(manifestPath)) {return [];}
  try {
    const pkg = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
      workspaces?: string[] | { packages?: string[] };
    };
    if (Array.isArray(pkg.workspaces)) {
      return pkg.workspaces.filter((item): item is string => typeof item === 'string');
    }
    if (Array.isArray(pkg.workspaces?.packages)) {
      return pkg.workspaces.packages.filter((item): item is string => typeof item === 'string');
    }
  } catch {
    return [];
  }
  const pnpm = join(dir, 'pnpm-workspace.yaml');
  if (existsSync(pnpm)) {
    return readFileSync(pnpm, 'utf8')
      .split('\n')
      .map((l) => l.replace(/^-+\s*/, '').trim())
      .filter((l) => l.length > 0 && !l.startsWith('packages:'));
  }
  return [];
}

function expandPattern(cwd: string, pattern: string): string[] {
  const normalized = pattern.replace(/\\/g, '/').replace(/^\.\//, '');
  if (!normalized.includes('*')) {return [normalized];}
  const slash = normalized.indexOf('/*');
  if (slash < 0) {return [];}
  const parent = normalized.slice(0, slash);
  try {
    return readdirSync(join(cwd, parent), { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => `${parent}/${entry.name}`)
      .sort();
  } catch {
    return [];
  }
}

/** Phase 554. True when workspaces expand to more than one package directory. */
export function isMultiWorkspaceProject(dir: string): boolean {
  const dirs = new Set<string>();
  for (const pattern of workspacePatterns(dir)) {
    for (const packageDir of expandPattern(dir, pattern)) {
      if (packageDir !== '' && packageDir !== '.') {dirs.add(packageDir);}
    }
  }
  return dirs.size > 1;
}

export function listWorkspaces(dir: string, opts: { experimental?: boolean } = {}): string[] {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM !== '1') {return [];}
  return workspacePatterns(dir);
}
