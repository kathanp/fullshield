import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { compareSemver } from '../modules/deps/semver.js';
import { parseLockfileGraph, type LockedPackage } from '../modules/deps/lockfile.js';

const execFileAsync = promisify(execFile);

export interface LockChange {
  name: string;
  change: 'added' | 'removed' | 'upgraded' | 'downgraded';
  oldVersion?: string;
  newVersion?: string;
  direct: boolean;
}

export interface IntroducedAdvisory {
  name: string;
  version: string;
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

const LOCK_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock'] as const;

export function diffLockedPackages(before: readonly LockedPackage[], after: readonly LockedPackage[], direct: ReadonlySet<string>): LockChange[] {
  const oldMap = new Map(before.map((pkg) => [pkg.name, pkg.version]));
  const newMap = new Map(after.map((pkg) => [pkg.name, pkg.version]));
  const names = [...new Set([...oldMap.keys(), ...newMap.keys()])].sort();
  const changes: LockChange[] = [];
  for (const name of names) {
    const oldVersion = oldMap.get(name);
    const newVersion = newMap.get(name);
    const isDirect = direct.has(name);
    if (oldVersion === undefined && newVersion !== undefined) {
      changes.push({ name, change: 'added', newVersion, direct: isDirect });
    } else if (oldVersion !== undefined && newVersion === undefined) {
      changes.push({ name, change: 'removed', oldVersion, direct: isDirect });
    } else if (oldVersion !== undefined && newVersion !== undefined && oldVersion !== newVersion) {
      const order = compareSemver(newVersion, oldVersion);
      changes.push({
        name,
        change: order >= 0 ? 'upgraded' : 'downgraded',
        oldVersion,
        newVersion,
        direct: isDirect,
      });
    }
  }
  return changes;
}

export function packagesFromLock(filename: string, contents: string): { packages: LockedPackage[]; direct: Set<string> } {
  const graph = parseLockfileGraph(filename, contents);
  return { packages: graph.packages, direct: new Set([...graph.directProd, ...graph.directDev]) };
}

export async function gitShow(cwd: string, spec: string, run = defaultGit): Promise<string> {
  return run(cwd, ['show', spec]);
}

async function defaultGit(cwd: string, args: string[]): Promise<string> {
  if (args[0] !== 'show') {throw new Error('deps-diff only runs git show');}
  const { stdout } = await execFileAsync('git', args, { cwd, encoding: 'utf8' });
  return stdout;
}

export async function lockAtRef(cwd: string, ref: string, run = defaultGit): Promise<{ file: string; text: string }> {
  for (const file of LOCK_NAMES) {
    try {
      const text = await gitShow(cwd, `${ref}:${file}`, run);
      if (text.length > 0) {return { file, text };}
    } catch {
      // try the next lockfile name
    }
  }
  throw new Error(`deps-diff cannot read a lockfile at ${ref} (FULLSHIELD_EXPERIMENTAL_DEPS_DIFF)`);
}

export function releaseAgeLabel(publishedAt: string | undefined, nowMs: number, minHours = 72): 'new-release' | 'aged' | 'unknown' {
  if (publishedAt === undefined) {return 'unknown';}
  const published = Date.parse(publishedAt);
  if (Number.isNaN(published)) {return 'unknown';}
  const hours = (nowMs - published) / 3_600_000;
  return hours < minHours ? 'new-release' : 'aged';
}
