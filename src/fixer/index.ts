import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

import { scan, type ScanOptions } from '../core/engine.js';
import type { Finding, ModuleName } from '../core/finding.js';
import { createFixBranch, isDirty, isGitRepo, listDirtyPaths } from './git.js';
import {
  collectManifestOverrides,
  withManifestOverride,
  type LockfileKind,
} from './override.js';
import { applyUnifiedDiff, proposeFix } from './patches.js';
import { mayWrite, verifyEnabled, verifyPatchedSource, type FixVerification } from './verify.js';

function detectLockKind(cwd: string): LockfileKind {
  if (existsSync(join(cwd, 'yarn.lock'))) return 'yarn';
  if (existsSync(join(cwd, 'pnpm-lock.yaml'))) return 'pnpm';
  return 'npm';
}

export interface FixOptions {
  cwd?: string;
  modules?: ModuleName[];
  apply?: boolean;
  force?: boolean;
  unsafe?: boolean;
  noBranch?: boolean;
  /** Phase 91. Write a patch that does not remove its finding. Never writes a patch that adds a finding. */
  forceUnverified?: boolean;
}

export interface FixPatch {
  file: string;
  ruleId: string;
  safe: boolean;
  diff: string;
  verified?: FixVerification;
}

export interface FixResult {
  applied: boolean;
  reverted: boolean;
  branch?: string;
  patches: FixPatch[];
  findings: Finding[];
  /** Set when an override was written to package.json. The lockfile is left unchanged. */
  notice?: string;
}

export async function runFix(options: FixOptions = {}): Promise<FixResult> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const scanOpts: ScanOptions = { cwd, modules: options.modules };
  const result = await scan(scanOpts);

  const byFile = new Map<string, string>();
  const patches: FixPatch[] = [];
  let appliedOverride = false;
  const lockKind = detectLockKind(cwd);

  for (const finding of result.findings) {
    if (finding.fix?.kind === 'dependency-override') {
      let manifest = byFile.get('package.json');
      if (manifest === undefined) {
        try {
          manifest = await readFile(join(cwd, 'package.json'), 'utf8');
          byFile.set('package.json', manifest);
        } catch {
          continue;
        }
      }
      patches.push({
        file: 'package.json',
        ruleId: finding.ruleId,
        safe: finding.fix.safe,
        diff: finding.fix.diff,
      });
      if (finding.fix.safe !== true && options.unsafe !== true) continue;
      const next = applyUnifiedDiff(manifest, finding.fix.diff);
      let merged = byFile.get('package.json') ?? manifest;
      for (const [name, version] of collectManifestOverrides(next)) {
        merged = withManifestOverride(merged, lockKind, name, version);
      }
      byFile.set('package.json', merged);
      appliedOverride = true;
      continue;
    }
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
    patches.push({ file: sourceFile, ruleId: finding.ruleId, safe: proposed.safe, diff: proposed.diff });
    if (proposed.safe !== true && options.unsafe !== true) continue;
    const after = applyUnifiedDiff(source, proposed.diff);
    if (verifyEnabled()) {
      const status = await verifyPatchedSource(sourceFile, source, after, finding.ruleId);
      const current = patches[patches.length - 1];
      if (current !== undefined) current.verified = status;
      if (!mayWrite(status, options.forceUnverified === true)) continue;
    }
    byFile.set(sourceFile, after);
  }

  const unused = result.metadata.unusedDirect?.packages ?? [];
  if (unused.length > 0) {
    let manifest = byFile.get('package.json');
    if (manifest === undefined) {
      try {
        manifest = await readFile(join(cwd, 'package.json'), 'utf8');
      } catch {
        manifest = undefined;
      }
    }
    if (manifest !== undefined) {
      const next = removeDirectDependencies(manifest, unused);
      const diff = dependencyRemovalDiff(manifest, unused);
      if (diff.length > 0) {
        patches.push({ file: 'package.json', ruleId: 'DEPS-VULN-001', safe: false, diff });
        if (options.unsafe === true) {
          byFile.set('package.json', next);
          appliedOverride = true;
        }
      }
    }
  }

  const notice = appliedOverride ? 'run npm install' : undefined;

  if (options.apply !== true) {
    return { applied: false, reverted: false, patches, findings: result.findings, notice };
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

  const dirtyPaths = (await isGitRepo(cwd)) ? await listDirtyPaths(cwd) : new Set<string>();
  const snapshots = new Map<string, Buffer | null>();

  for (const [file, contents] of byFile) {
    if (dirtyPaths.has(file)) continue;
    const abs = join(cwd, file);
    let original: Buffer | null = null;
    try {
      original = await readFile(abs);
    } catch {
      original = null;
    }
    if (original !== null && original.toString('utf8') === contents) continue;
    snapshots.set(file, original);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, contents, 'utf8');
  }

  const testFailed = verifyEnabled() ? false : runProjectTests(cwd);
  if (testFailed) {
    await restoreSnapshots(cwd, snapshots);
    return { applied: false, reverted: true, branch, patches, findings: result.findings };
  }

  return { applied: true, reverted: false, branch, patches, findings: result.findings, notice };
}

async function restoreSnapshots(cwd: string, snapshots: Map<string, Buffer | null>): Promise<void> {
  for (const [file, original] of snapshots) {
    const abs = join(cwd, file);
    if (original === null) {
      await unlink(abs).catch(() => undefined);
    } else {
      await writeFile(abs, original);
    }
  }
}

function dependencyRemovalDiff(manifest: string, names: readonly string[]): string {
  const drop = names.map((name) => `"${name}"`);
  const removed = manifest.split('\n').filter((line) => drop.some((token) => line.includes(token)));
  if (removed.length === 0) return '';
  return ['--- a/package.json', '+++ b/package.json', ...removed.map((line) => `-${line}`)].join('\n');
}

function removeDirectDependencies(manifest: string, names: readonly string[]): string {
  let parsed: { dependencies?: Record<string, unknown> };
  try {
    parsed = JSON.parse(manifest) as { dependencies?: Record<string, unknown> };
  } catch {
    return manifest;
  }
  if (parsed.dependencies === undefined || typeof parsed.dependencies !== 'object') return manifest;
  const drop = new Set(names);
  const next: Record<string, unknown> = {};
  for (const [name, version] of Object.entries(parsed.dependencies)) {
    if (!drop.has(name)) next[name] = version;
  }
  parsed.dependencies = next;
  const trailing = manifest.endsWith('\n') ? '\n' : '';
  return `${JSON.stringify(parsed, null, 2)}${trailing}`;
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
