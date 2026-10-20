import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { parseCacheDir } from '../../core/parse-pool.js';
import { packageVersion } from '../../core/version.js';
import { usageInSource, type PackageUsage } from './reachability.js';

interface StoredUsage {
  v: 1;
  rows: Array<{ name: string; called: boolean }>;
}

export function callGraphDir(): string {
  return process.env.FULLSHIELD_CALL_GRAPH_DIR ?? join(parseCacheDir(), 'callgraph');
}

export function callGraphConfigHash(maxFileBytes: number): string {
  return createHash('sha256').update(String(maxFileBytes)).digest('hex');
}

function usageKey(source: string, configHash: string): string {
  return createHash('sha256')
    .update(packageVersion())
    .update('\0')
    .update(configHash)
    .update('\0')
    .update(source)
    .digest('hex');
}

function usagePath(key: string): string {
  return join(callGraphDir(), `${key}.json`);
}

function discard(key: string): void {
  rmSync(usagePath(key), { force: true });
}

function readUsage(key: string): Map<string, PackageUsage> | undefined {
  let text: string;
  try {
    text = readFileSync(usagePath(key), 'utf8');
  } catch {
    return undefined;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    discard(key);
    return undefined;
  }
  if (typeof raw !== 'object' || raw === null) {
    discard(key);
    return undefined;
  }
  const row = raw as Partial<StoredUsage>;
  if (row.v !== 1 || !Array.isArray(row.rows)) {
    discard(key);
    return undefined;
  }
  const usage = new Map<string, PackageUsage>();
  for (const item of row.rows) {
    if (item === null || typeof item !== 'object') {
      discard(key);
      return undefined;
    }
    const name = (item as { name?: unknown }).name;
    const called = (item as { called?: unknown }).called;
    if (typeof name !== 'string' || typeof called !== 'boolean') {
      discard(key);
      return undefined;
    }
    usage.set(name, { imported: true, called });
  }
  return usage;
}

function writeUsage(key: string, usage: Map<string, PackageUsage>): void {
  const dir = callGraphDir();
  mkdirSync(dir, { recursive: true });
  const stored: StoredUsage = {
    v: 1,
    rows: [...usage.entries()]
      .map(([name, row]) => ({ name, called: row.called }))
      .sort((a, b) => a.name.localeCompare(b.name)),
  };
  writeFileSync(usagePath(key), JSON.stringify(stored));
}

function cachedUsageInSource(source: string, configHash: string): Map<string, PackageUsage> {
  const key = usageKey(source, configHash);
  const cached = readUsage(key);
  if (cached !== undefined) {return cached;}
  const fresh = usageInSource(source);
  writeUsage(key, fresh);
  return fresh;
}

/** Same map as `indexPackageUsage`, with one cache file per source. A bad file is deleted. */
export function indexPackageUsageCached(
  sources: ReadonlyMap<string, string>,
  configHash: string,
): Map<string, PackageUsage> {
  const usage = new Map<string, PackageUsage>();
  for (const source of sources.values()) {
    for (const [pkg, row] of cachedUsageInSource(source, configHash)) {
      const prev = usage.get(pkg) ?? { imported: false, called: false };
      usage.set(pkg, { imported: true, called: prev.called || row.called });
    }
  }
  return usage;
}
