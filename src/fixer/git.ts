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

export async function createFixBranch(cwd: string): Promise<string> {
  const name = `fullshield/fixes-${Date.now()}`;
  await execFileAsync('git', ['-C', cwd, 'checkout', '-b', name]);
  return name;
}

export async function revertWorktree(cwd: string): Promise<void> {
  // Restore tracked files only. Never delete user files (`git clean` is out).
  await execFileAsync('git', ['-C', cwd, 'checkout', '--', '.']);
}
