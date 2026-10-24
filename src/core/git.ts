import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/** Run git and return its status. A non-zero status is a result, not a thrown error. */
export async function gitOutput(cwd: string, args: string[]): Promise<{ status: number; stdout: string }> {
  try {
    const { stdout } = await execFileAsync('git', ['-C', cwd, ...args], { encoding: 'utf8' });
    return { status: 0, stdout };
  } catch (error) {
    const failed = error as { stdout?: unknown; status?: unknown };
    return {
      status: typeof failed.status === 'number' ? failed.status : 1,
      stdout: typeof failed.stdout === 'string' ? failed.stdout : '',
    };
  }
}

/** List files staged in the git index (pre-commit mode), relative to cwd. */
export async function listStagedFiles(cwd: string): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync('git', [
      '-C',
      cwd,
      'diff',
      '--cached',
      '--name-only',
      '--diff-filter=ACMR',
      '-z',
    ]);
    return stdout.split('\u0000').filter((f) => f.length > 0);
  } catch (error) {
    throw new Error(
      `--staged requires a git repository and the git CLI (${
        error instanceof Error ? error.message.split('\n')[0] ?? 'git failed' : String(error)
      })`,
    );
  }
}
