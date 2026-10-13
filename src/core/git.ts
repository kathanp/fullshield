import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

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
