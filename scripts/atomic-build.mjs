/**
 * Build into a staging directory in this repo, then rename it onto dist/.
 * tsup's clean step therefore never deletes dist/ while another reader uses it.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, renameSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const staging = mkdtempSync(join(root, '.fullshield-dist-'));
const tsup = join(root, 'node_modules', 'tsup', 'dist', 'cli-default.js');
const built = spawnSync(process.execPath, [tsup, '--out-dir', staging], {
  cwd: root,
  stdio: 'inherit',
});
if (built.status !== 0) {
  rmSync(staging, { recursive: true, force: true });
  process.exit(built.status ?? 1);
}

const dist = join(root, 'dist');
const previous = join(root, '.fullshield-dist-previous');
if (existsSync(previous)) rmSync(previous, { recursive: true, force: true });
if (existsSync(dist)) renameSync(dist, previous);
renameSync(staging, dist);
if (existsSync(previous)) rmSync(previous, { recursive: true, force: true });
