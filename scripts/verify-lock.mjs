import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

function verifyLockPath(root) {
  return process.env.FULLSHIELD_VERIFY_LOCK || join(root, '.fullshield-verify.lock');
}

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Exit FS-E010 when another live verify holds this worktree. */
export function acquireVerifyLock(root) {
  const path = verifyLockPath(root);
  if (existsSync(path)) {
    const pid = Number(readFileSync(path, 'utf8').trim());
    if (pidAlive(pid) && pid !== process.pid) {
      console.error(`fullshield: FS-E010 another verify is already running in this worktree (pid ${pid})`);
      process.exit(1);
    }
  }
  writeFileSync(path, `${process.pid}\n`);
  return path;
}

export function releaseVerifyLock(root) {
  const path = verifyLockPath(root);
  if (!existsSync(path)) return;
  const pid = Number(readFileSync(path, 'utf8').trim());
  if (pid === process.pid) rmSync(path, { force: true });
}

/** `git diff --exit-code -- src test`. Returns the diff text when the tree is dirty. */
export function srcTestDiff(root) {
  const result = spawnSync('git', ['diff', '--exit-code', '--', 'src', 'test'], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.status === 0) return '';
  return `${result.stdout ?? ''}${result.stderr ?? ''}`;
}

export function assertSrcTestClean(root, what) {
  const diff = srcTestDiff(root);
  if (diff === '') return;
  console.error(`fullshield: FS-E011 ${what} left src or test dirty`);
  console.error(diff);
  process.exit(1);
}
