import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import { makeFindingId, type Finding } from '../core/finding.js';
import { releaseAgeLabel } from '../deps-diff/index.js';
import { compareSemver } from '../modules/deps/semver.js';
import { ALLOWED_HOSTS } from '../net/hosts.js';
import { assertRegistryUrl } from '../supply/index.js';

export const PROVENANCE_FLAG = 'FULLSHIELD_EXPERIMENTAL_PROVENANCE';

export type ProvenanceSignal = 'provenance-regression' | 'publisher-change' | 'new-release';

export interface ProvenanceRow {
  name: string;
  version: string;
  data: 'known' | 'unknown';
  signals: ProvenanceSignal[];
}

export interface ProvenanceQuery {
  cacheDir: string;
  offline: boolean;
  fetchImpl?: (input: string | URL, init?: RequestInit) => Promise<Response>;
  sleep?: (ms: number) => Promise<void>;
  concurrency?: number;
  now?: () => number;
  previousCount?: number;
  minReleaseAgeHours?: number;
}

interface VersionInfo {
  publisher?: string;
  provenance: 'present' | 'absent';
}

interface Attempt {
  body?: unknown;
  retryMs?: number;
}

const SIGNAL_TEXT: Record<ProvenanceSignal, string> = {
  'provenance-regression': 'earlier versions listed dist.attestations and this version does not',
  'publisher-change': 'the publishing user published none of the previous versions in the window',
  'new-release': 'the version is inside the release-age window',
};

export function provenanceEnabled(): boolean {
  return process.env[PROVENANCE_FLAG] === '1';
}

export function registryCachePath(cacheDir: string, name: string): string {
  return join(cacheDir, 'registry', `${name.replaceAll('/', '__')}.json`);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
  return value as Record<string, unknown>;
}

function packumentRecord(raw: unknown): Record<string, unknown> | undefined {
  const doc = asRecord(raw);
  if (doc === undefined) {return undefined;}
  const nested = asRecord(doc.packument);
  if (nested !== undefined && asRecord(nested.versions) !== undefined) {return nested;}
  if (asRecord(doc.versions) !== undefined) {return doc;}
  return undefined;
}

function stringField(record: Record<string, unknown> | undefined, key: string): string | undefined {
  if (record === undefined) {return undefined;}
  const value = record[key];
  if (typeof value !== 'string') {return undefined;}
  return value;
}

function registryHost(): string | undefined {
  for (const host of ALLOWED_HOSTS) {
    if (host === 'registry.npmjs.org') {return host;}
  }
  return undefined;
}

function packumentUrl(name: string): string | undefined {
  const host = registryHost();
  if (host === undefined) {return undefined;}
  const url = `https://${host}/${encodeURIComponent(name)}`;
  assertRegistryUrl(url);
  return url;
}

export function releaseFactsFromCache(
  raw: unknown,
  version: string | undefined,
): { publishedAt?: string; hasInstallScript?: boolean } {
  const doc = asRecord(raw);
  if (doc === undefined) {return {};}
  if (typeof doc.time === 'string') {
    return {
      publishedAt: doc.time,
      hasInstallScript: typeof doc.hasInstallScript === 'boolean' ? doc.hasInstallScript : undefined,
    };
  }
  return factsFromPackument(doc, version);
}

function factsFromPackument(
  doc: Record<string, unknown>,
  version: string | undefined,
): { publishedAt?: string; hasInstallScript?: boolean } {
  const body = packumentRecord(doc);
  const publishedAt = version === undefined ? undefined : stringField(asRecord(body?.time), version);
  if (typeof doc.hasInstallScript === 'boolean') {
    return { publishedAt, hasInstallScript: doc.hasInstallScript };
  }
  return { publishedAt, hasInstallScript: scriptsFlag(body, version) };
}

function scriptsFlag(body: Record<string, unknown> | undefined, version: string | undefined): boolean | undefined {
  if (body === undefined || version === undefined) {return undefined;}
  const entry = asRecord(asRecord(body.versions)?.[version]);
  if (entry === undefined) {return undefined;}
  const scripts = asRecord(entry.scripts);
  if (scripts === undefined) {return false;}
  return ['preinstall', 'install', 'postinstall'].some((key) => typeof scripts[key] === 'string');
}

function publisherName(entry: Record<string, unknown>): string | undefined {
  const user = asRecord(entry._npmUser) ?? asRecord(entry.npmUser);
  if (user === undefined || typeof user.name !== 'string') {return undefined;}
  const trimmed = user.name.trim();
  if (trimmed.length === 0) {return undefined;}
  return trimmed;
}

function attestation(entry: Record<string, unknown>): 'present' | 'absent' {
  const dist = asRecord(entry.dist);
  if (dist === undefined || dist.attestations === undefined || dist.attestations === null) {return 'absent';}
  return 'present';
}

function readVersion(entry: Record<string, unknown>): VersionInfo {
  return { publisher: publisherName(entry), provenance: attestation(entry) };
}

function earlierVersions(version: string, versions: Record<string, unknown>): VersionInfo[] {
  const names = Object.keys(versions).filter((item) => item !== version && compareSemver(item, version) < 0);
  names.sort((left, right) => compareSemver(right, left));
  const out: VersionInfo[] = [];
  for (const name of names) {
    const entry = asRecord(versions[name]);
    if (entry !== undefined) {out.push(readVersion(entry));}
  }
  return out;
}

function regressed(installed: VersionInfo, earlier: readonly VersionInfo[]): boolean {
  if (installed.provenance !== 'absent') {return false;}
  return earlier.some((item) => item.provenance === 'present');
}

function publisherChanged(installed: VersionInfo, earlier: readonly VersionInfo[], limit: number): boolean {
  if (installed.publisher === undefined) {return false;}
  const window = earlier.slice(0, limit);
  if (window.length === 0) {return false;}
  for (const item of window) {
    if (item.publisher === undefined || item.publisher === installed.publisher) {return false;}
  }
  return true;
}

function evaluatePackage(
  name: string,
  version: string,
  raw: unknown | undefined,
  opts: ProvenanceQuery,
): ProvenanceRow {
  const missing: ProvenanceRow = { name, version, data: 'unknown', signals: [] };
  const body = raw === undefined ? undefined : packumentRecord(raw);
  const versions = body === undefined ? undefined : asRecord(body.versions);
  const entry = versions === undefined ? undefined : asRecord(versions[version]);
  if (body === undefined || versions === undefined || entry === undefined) {return missing;}
  const signals: ProvenanceSignal[] = [];
  const earlier = earlierVersions(version, versions);
  const installed = readVersion(entry);
  if (regressed(installed, earlier)) {signals.push('provenance-regression');}
  if (publisherChanged(installed, earlier, opts.previousCount ?? 10)) {signals.push('publisher-change');}
  const nowMs = opts.now === undefined ? Date.now() : opts.now();
  const age = releaseAgeLabel(stringField(asRecord(body.time), version), nowMs, opts.minReleaseAgeHours ?? 72);
  if (age === 'new-release') {signals.push('new-release');}
  return { name, version, data: 'known', signals };
}

function retryAfterMs(header: string | null, nowMs: number): number | undefined {
  if (header === null) {return undefined;}
  const trimmed = header.trim();
  if (trimmed.length === 0) {return undefined;}
  if (/^\d+$/.test(trimmed)) {return Number(trimmed) * 1000;}
  const when = Date.parse(trimmed);
  if (Number.isNaN(when)) {return undefined;}
  const delta = when - nowMs;
  return delta < 0 ? 0 : delta;
}

async function attempt(
  url: string,
  fetchImpl: NonNullable<ProvenanceQuery['fetchImpl']>,
  now: () => number,
): Promise<Attempt | undefined> {
  let response: Response;
  try {
    response = await fetchImpl(url, { redirect: 'manual' });
  } catch {
    return undefined;
  }
  if (response.status >= 300 && response.status < 400) {return undefined;}
  if (response.status === 429 || response.status === 503) {
    const retryMs = retryAfterMs(response.headers.get('retry-after'), now());
    if (retryMs === undefined) {return undefined;}
    return { retryMs };
  }
  if (!response.ok) {return undefined;}
  try {
    return { body: await response.json() };
  } catch {
    return undefined;
  }
}

async function fetchPackument(
  name: string,
  fetchImpl: NonNullable<ProvenanceQuery['fetchImpl']>,
  sleep: (ms: number) => Promise<void>,
  now: () => number,
): Promise<unknown> {
  const url = packumentUrl(name);
  if (url === undefined) {return undefined;}
  const first = await attempt(url, fetchImpl, now);
  if (first === undefined) {return undefined;}
  if (first.retryMs === undefined) {return first.body;}
  await sleep(first.retryMs);
  const second = await attempt(url, fetchImpl, now);
  if (second === undefined || second.retryMs !== undefined) {return undefined;}
  return second.body;
}

async function guardedFetch(input: string | URL, init?: RequestInit): Promise<Response> {
  const url = String(input);
  assertRegistryUrl(url);
  return fetch(url, init);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function mapLimit(items: readonly string[], limit: number, fn: (name: string) => Promise<void>): Promise<void> {
  const cap = Math.min(8, Math.max(1, limit));
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const item = items[next];
      next += 1;
      if (item === undefined) {return;}
      await fn(item);
    }
  };
  const jobs: Array<Promise<void>> = [];
  const workers = Math.min(cap, items.length);
  for (let i = 0; i < workers; i += 1) {jobs.push(worker());}
  await Promise.all(jobs);
}

async function readPackument(file: string): Promise<unknown> {
  try {
    const raw: unknown = JSON.parse(await readFile(file, 'utf8'));
    return packumentRecord(raw);
  } catch {
    return undefined;
  }
}

async function writePackument(file: string, body: unknown): Promise<void> {
  const record = asRecord(body);
  const tags = record === undefined ? undefined : asRecord(record['dist-tags']);
  const latest = tags !== undefined && typeof tags.latest === 'string' ? tags.latest : await preservedLatest(file);
  const payload: Record<string, unknown> = { fetchedAt: new Date().toISOString(), packument: body };
  if (latest !== undefined) {payload.latest = latest;}
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify(payload));
}

async function preservedLatest(file: string): Promise<string | undefined> {
  try {
    const existing = asRecord(JSON.parse(await readFile(file, 'utf8')));
    if (existing !== undefined && typeof existing.latest === 'string') {return existing.latest;}
  } catch {
    return undefined;
  }
  return undefined;
}

async function loadPackuments(names: readonly string[], opts: ProvenanceQuery): Promise<Map<string, unknown>> {
  const out = new Map<string, unknown>();
  const missing: string[] = [];
  for (const name of names) {
    const cached = await readPackument(registryCachePath(opts.cacheDir, name));
    if (cached !== undefined) {out.set(name, cached);}
    else {missing.push(name);}
  }
  if (opts.offline || missing.length === 0) {return out;}
  const fetchImpl = opts.fetchImpl ?? guardedFetch;
  const sleep = opts.sleep ?? delay;
  const now = opts.now ?? Date.now;
  await mapLimit(missing, opts.concurrency ?? 8, async (name) => {
    const body = await fetchPackument(name, fetchImpl, sleep, now);
    if (body === undefined) {return;}
    await writePackument(registryCachePath(opts.cacheDir, name), body);
    out.set(name, body);
  });
  return out;
}

function uniqueNames(packages: readonly { name: string }[]): string[] {
  const seen = new Set<string>();
  const names: string[] = [];
  for (const pkg of packages) {
    if (seen.has(pkg.name)) {continue;}
    seen.add(pkg.name);
    names.push(pkg.name);
  }
  return names;
}

function toFinding(row: ProvenanceRow, lockFile: string): Finding | undefined {
  if (row.data !== 'known' || row.signals.length === 0) {return undefined;}
  const detail = row.signals.map((signal) => `${signal}: ${SIGNAL_TEXT[signal]}`).join('; ');
  const snippet = `${row.name}@${row.version}`;
  const message = `${snippet} registry signal (${detail}). Informational only.`;
  return {
    id: makeFindingId('SUPPLY-PROV-001', lockFile, message),
    ruleId: 'SUPPLY-PROV-001',
    module: 'deps',
    title: `Registry provenance signal for ${snippet}`,
    severity: 'medium',
    confidence: 'medium',
    file: lockFile,
    snippet,
    message,
    remediation: 'Review the registry packument for this version. This signal is informational.',
  };
}

export async function provenanceFindingsForScan(
  packages: readonly { name: string; version: string }[],
  lockFile: string,
  opts: ProvenanceQuery,
): Promise<{ findings: Finding[]; rows: ProvenanceRow[] }> {
  const loaded = await loadPackuments(uniqueNames(packages), opts);
  const rows = packages.map((pkg) => evaluatePackage(pkg.name, pkg.version, loaded.get(pkg.name), opts));
  const findings: Finding[] = [];
  for (const row of rows) {
    const finding = toFinding(row, lockFile);
    if (finding !== undefined) {findings.push(finding);}
  }
  return { findings, rows };
}
