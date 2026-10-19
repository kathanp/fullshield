import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';

import { assertRegistryUrl } from '../supply/index.js';
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
  if (args[0] !== 'show') throw new Error('deps-diff only runs git show');
  const { stdout } = await execFileAsync('git', args, { cwd, encoding: 'utf8' });
  return stdout;
}

export async function lockAtRef(cwd: string, ref: string, run = defaultGit): Promise<{ file: string; text: string }> {
  for (const file of LOCK_NAMES) {
    try {
      const text = await gitShow(cwd, `${ref}:${file}`, run);
      if (text.length > 0) return { file, text };
    } catch {
      // try the next lockfile name
    }
  }
  throw new Error(`deps-diff cannot read a lockfile at ${ref} (FULLSHIELD_EXPERIMENTAL_DEPS_DIFF)`);
}

export function advisoriesCleared(before: readonly IntroducedAdvisory[], after: readonly IntroducedAdvisory[]): IntroducedAdvisory[] {
  const still = new Set(after.map((row) => `${row.name}\0${row.id}`));
  const seen = new Set<string>();
  const cleared: IntroducedAdvisory[] = [];
  for (const row of before) {
    const key = `${row.name}\0${row.id}`;
    if (still.has(key) || seen.has(key)) continue;
    seen.add(key);
    cleared.push(row);
  }
  return cleared;
}

export interface RegistryRecord {
  publishedAt?: string;
  hasInstallScript?: boolean;
  latest?: string;
}

export function registryPackageUrl(name: string): string {
  const encoded = name.startsWith('@') ? name.replace('/', '%2f') : name;
  const url = `https://registry.npmjs.org/${encoded}`;
  assertRegistryUrl(url);
  return url;
}

export async function registryRecord(
  name: string,
  version: string | undefined,
  opts: { cacheDir: string; offline: boolean; fetchImpl?: typeof fetch },
): Promise<RegistryRecord> {
  const cacheFile = join(opts.cacheDir, 'registry', `${name.replaceAll('/', '__')}.json`);
  const cached = await readRegistryCache(cacheFile);
  if (cached.publishedAt !== undefined || cached.latest !== undefined || cached.hasInstallScript !== undefined) return cached;
  if (opts.offline) return {};
  try {
    const response = await (opts.fetchImpl ?? fetch)(registryPackageUrl(name));
    if (!response.ok) return {};
    const body = (await response.json()) as {
      'dist-tags'?: { latest?: string };
      time?: Record<string, string>;
      versions?: Record<string, { scripts?: Record<string, string> }>;
    };
    const latest = typeof body['dist-tags']?.latest === 'string' ? body['dist-tags'].latest : undefined;
    const publishedAt = version !== undefined ? body.time?.[version] : undefined;
    const scripts = version !== undefined ? body.versions?.[version]?.scripts : undefined;
    const hasInstallScript =
      scripts === undefined ? undefined : ['preinstall', 'install', 'postinstall'].some((key) => scripts[key] !== undefined);
    const record: RegistryRecord = { publishedAt, hasInstallScript, latest };
    try {
      await mkdir(dirname(cacheFile), { recursive: true });
      await writeFile(cacheFile, JSON.stringify({ time: publishedAt, hasInstallScript, latest }));
    } catch {
      // A cache write never changes the answer.
    }
    return record;
  } catch {
    return {};
  }
}

async function readRegistryCache(file: string): Promise<RegistryRecord> {
  try {
    const raw = JSON.parse(await readFile(file, 'utf8')) as { time?: string; hasInstallScript?: boolean; latest?: string };
    return {
      publishedAt: typeof raw.time === 'string' ? raw.time : undefined,
      hasInstallScript: typeof raw.hasInstallScript === 'boolean' ? raw.hasInstallScript : undefined,
      latest: typeof raw.latest === 'string' ? raw.latest : undefined,
    };
  } catch {
    return {};
  }
}

export function releaseAgeLabel(publishedAt: string | undefined, nowMs: number, minHours = 72): 'new-release' | 'aged' | 'unknown' {
  if (publishedAt === undefined) return 'unknown';
  const published = Date.parse(publishedAt);
  if (Number.isNaN(published)) return 'unknown';
  const hours = (nowMs - published) / 3_600_000;
  return hours < minHours ? 'new-release' : 'aged';
}
