import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

import { scan, type ScanOptions } from '../core/engine.js';
import type { Finding, ModuleName } from '../core/finding.js';
import { applyUnifiedDiff, proposeFix } from './patches.js';
import { createFixBranch, isDirty, isGitRepo, revertWorktree } from './git.js';

export interface FixOptions {
  cwd?: string;
  modules?: ModuleName[];
  apply?: boolean;
  force?: boolean;
  unsafe?: boolean;
  noBranch?: boolean;
}

export interface FixPatch {
  file: string;
  ruleId: string;
  safe: boolean;
  diff: string;
}

export interface FixResult {
  applied: boolean;
  reverted: boolean;
  branch?: string;
  patches: FixPatch[];
  findings: Finding[];
}

export async function runFix(options: FixOptions = {}): Promise<FixResult> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const scanOpts: ScanOptions = { cwd, modules: options.modules };
  const result = await scan(scanOpts);

  const byFile = new Map<string, string>();
  const patches: FixPatch[] = [];

  for (const finding of result.findings) {
    const file = finding.file;
    if (file === undefined) continue;
    if (!byFile.has(file)) {
      try {
        byFile.set(file, await readFile(join(cwd, file), 'utf8'));
      } catch {
        if (finding.ruleId === 'SECRET-ENVFILE-001') {
          byFile.set('.gitignore', await readFile(join(cwd, '.gitignore'), 'utf8').catch(() => ''));
        } else {
          continue;
        }
      }
    }
    const sourceFile = finding.ruleId === 'SECRET-ENVFILE-001' && file === '.env' ? '.gitignore' : file;
    const source = byFile.get(sourceFile) ?? byFile.get(file);
    if (source === undefined) continue;
    const proposed = proposeFix(
      sourceFile === file ? finding : { ...finding, file: sourceFile },
      source,
    );
    if (proposed === undefined) continue;
    if (proposed.safe !== true && options.unsafe !== true) continue;
    const after = applyUnifiedDiff(source, proposed.diff);
    byFile.set(sourceFile, after);
    patches.push({ file: sourceFile, ruleId: finding.ruleId, safe: proposed.safe, diff: proposed.diff });
  }

  if (options.apply !== true) {
    return { applied: false, reverted: false, patches, findings: result.findings };
  }

  if (!(await isGitRepo(cwd)) && options.force !== true) {
    throw new Error('fix --apply requires a git repository (or pass --force)');
  }
  if ((await isGitRepo(cwd)) && (await isDirty(cwd)) && options.force !== true) {
    throw new Error('fix --apply refused: git working tree is dirty (use --force to override)');
  }

  let branch: string | undefined;
  if (options.noBranch !== true && (await isGitRepo(cwd))) {
    branch = await createFixBranch(cwd);
  }

  for (const [file, contents] of byFile) {
    const abs = join(cwd, file);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, contents, 'utf8');
  }

  const testFailed = runProjectTests(cwd);
  if (testFailed && (await isGitRepo(cwd))) {
    await revertWorktree(cwd);
    return { applied: false, reverted: true, branch, patches, findings: result.findings };
  }

  return { applied: !testFailed, reverted: false, branch, patches, findings: result.findings };
}

function runProjectTests(cwd: string): boolean {
  let pkg: { scripts?: { test?: string } };
  try {
    pkg = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8')) as {
      scripts?: { test?: string };
    };
  } catch {
    return false;
  }
  if (typeof pkg.scripts?.test !== 'string' || pkg.scripts.test.length === 0) return false;
  const result = spawnSync('npm', ['test'], { cwd, encoding: 'utf8', shell: process.platform === 'win32' });
  return result.status !== 0;
}
