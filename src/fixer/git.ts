import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export async function isGitRepo(cwd: string): Promise<boolean> {
  try {
    await execFileAsync('git', ['-C', cwd, 'rev-parse', '--is-inside-work-tree']);
    return true;
  } catch {
    return false;
  }
}

export async function isDirty(cwd: string): Promise<boolean> {
  const { stdout } = await execFileAsync('git', ['-C', cwd, 'status', '--porcelain']);
  return stdout.trim().length > 0;
}

/**
 * Paths with uncommitted changes (modified, staged, untracked, renamed).
 * Paths are relative to `cwd` (the scan root).
 */
export async function listDirtyPaths(cwd: string): Promise<Set<string>> {
  const { stdout } = await execFileAsync('git', ['-C', cwd, 'status', '--porcelain']);
  const dirty = new Set<string>();
  for (const line of stdout.split('\n')) {
    if (line.length < 4) {continue;}
    const rest = line.slice(3);
    for (const raw of rest.split(' -> ')) {
      const path = unquoteGitPath(raw.trim());
      if (path.length > 0) {dirty.add(path);}
    }
  }
  return dirty;
}

function unquoteGitPath(path: string): string {
  if (path.startsWith('"') && path.endsWith('"') && path.length >= 2) {
    try {
      return JSON.parse(path) as string;
    } catch {
      return path.slice(1, -1);
    }
  }
  return path;
}

export async function createFixBranch(cwd: string): Promise<string> {
  const name = `fullshield/fixes-${Date.now()}`;
  await execFileAsync('git', ['-C', cwd, 'checkout', '-b', name]);
  return name;
}
