import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export function listWorkspaces(dir: string, opts: { experimental?: boolean } = {}): string[] {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM !== '1') {return [];}
  const manifestPath = join(dir, 'package.json');
  if (!existsSync(manifestPath)) {return [];}
  try {
    const pkg = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
      workspaces?: string[] | { packages?: string[] };
    };
    if (Array.isArray(pkg.workspaces)) {return pkg.workspaces;}
    if (Array.isArray(pkg.workspaces?.packages)) {return pkg.workspaces.packages;}
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
