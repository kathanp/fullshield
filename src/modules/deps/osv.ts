import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import type { LockedPackage } from './lockfile.js';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
const TTL_MS = 24 * 60 * 60 * 1000;
const BATCH_SIZE = 100;

export interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  database_specific?: { severity?: string; malicious?: unknown };
  severity?: Array<{ type?: string; score?: string }>;
  affected?: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
  references?: Array<{ type?: string; url?: string }>;
}

export interface CacheEntry {
  fetchedAt: string;
  vulns: OsvVuln[];
}

export interface OsvHit {
  pkg: LockedPackage;
  vulns: OsvVuln[];
}

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

/** MAL- OSV ids or database_specific.malicious — install-time malware, not a CVE. */
export function isMaliciousAdvisory(vuln: Pick<OsvVuln, 'id' | 'database_specific' | 'aliases'>): boolean {
  if (vuln.id.startsWith('MAL-')) return true;
  if ((vuln.aliases ?? []).some((a) => a.startsWith('MAL-'))) return true;
  const flag = vuln.database_specific?.malicious;
  if (flag === true) return true;
  if (flag !== null && typeof flag === 'object') return true;
  return false;
}

export interface QueryOsvOptions {
  cacheDir: string;
  offline: boolean;
  now?: () => number;
  fetchImpl?: FetchLike;
}

function cachePath(cacheDir: string, pkg: LockedPackage): string {
  return join(cacheDir, 'osv', `${pkg.name.replaceAll('/', '__')}@${pkg.version}.json`);
}

async function readCache(cacheDir: string, pkg: LockedPackage): Promise<CacheEntry | undefined> {
  try {
    const raw = JSON.parse(await readFile(cachePath(cacheDir, pkg), 'utf8')) as CacheEntry;
    if (typeof raw.fetchedAt !== 'string' || !Array.isArray(raw.vulns)) return undefined;
    return raw;
  } catch {
    return undefined;
  }
}

async function writeCache(cacheDir: string, pkg: LockedPackage, entry: CacheEntry): Promise<void> {
  const file = cachePath(cacheDir, pkg);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify(entry, null, 2));
}

interface BatchResult {
  vulns?: Array<{ id?: string }>;
}

async function queryBatch(
  fetchImpl: FetchLike,
  packages: LockedPackage[],
): Promise<BatchResult[]> {
  const response = await fetchImpl(OSV_BATCH_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      queries: packages.map((pkg) => ({
        package: { name: pkg.name, ecosystem: 'npm' },
        version: pkg.version,
      })),
    }),
  });
  if (!response.ok) {
    throw new Error(`OSV querybatch failed: HTTP ${response.status}`);
  }
  const body = (await response.json()) as { results?: BatchResult[] };
  return body.results ?? [];
}

async function fetchVuln(fetchImpl: FetchLike, id: string): Promise<OsvVuln | undefined> {
  const response = await fetchImpl(`${OSV_VULN_URL}${encodeURIComponent(id)}`);
  if (!response.ok) return undefined;
  const body = (await response.json()) as OsvVuln;
  if (typeof body.id !== 'string') return undefined;
  return body;
}

/**
 * Look up OSV vulns for the given packages. Results are cached under
 * `{cacheDir}/osv/{name}@{version}.json` with a 24h TTL. `--offline` never
 * contacts the network and never invents a finding on a cache miss.
 */
export async function queryOsv(
  packages: LockedPackage[],
  options: QueryOsvOptions,
): Promise<OsvHit[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  const hits: OsvHit[] = [];
  const missing: LockedPackage[] = [];

  for (const pkg of packages) {
    const cached = await readCache(options.cacheDir, pkg);
    const fresh =
      cached !== undefined &&
      (options.offline || now() - Date.parse(cached.fetchedAt) < TTL_MS);
    if (fresh && cached !== undefined) {
      if (cached.vulns.length > 0) hits.push({ pkg, vulns: cached.vulns });
      continue;
    }
    if (!options.offline) missing.push(pkg);
  }

  for (let i = 0; i < missing.length; i += BATCH_SIZE) {
    const chunk = missing.slice(i, i + BATCH_SIZE);
    let results: BatchResult[];
    try {
      results = await queryBatch(fetchImpl, chunk);
    } catch {
      continue;
    }
    for (let j = 0; j < chunk.length; j += 1) {
      const pkg = chunk[j];
      if (pkg === undefined) continue;
      const ids = (results[j]?.vulns ?? [])
        .map((v) => v.id)
        .filter((id): id is string => typeof id === 'string' && id.length > 0);
      const vulns: OsvVuln[] = [];
      for (const id of ids) {
        try {
          const detail = await fetchVuln(fetchImpl, id);
          if (detail !== undefined) vulns.push(detail);
        } catch {
          // Keep going; a single detail fetch must not invent or drop the rest.
        }
      }
      await writeCache(options.cacheDir, pkg, {
        fetchedAt: new Date(now()).toISOString(),
        vulns,
      });
      if (vulns.length > 0) hits.push({ pkg, vulns });
    }
  }

  return hits;
}
