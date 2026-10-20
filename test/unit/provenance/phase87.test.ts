import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { severityRank } from '../../../src/core/finding.js';
import { releaseAgeLabel } from '../../../src/deps-diff/index.js';
import {
  PROVENANCE_FLAG,
  provenanceFindingsForScan,
  registryCachePath,
  releaseFactsFromCache,
  type ProvenanceQuery,
} from '../../../src/provenance/index.js';

const NOW = Date.parse('2026-10-19T12:00:00.000Z');
const YOUNG = '2026-10-19T10:00:00.000Z';
const AGED = '2026-01-01T00:00:00.000Z';
const dirs: string[] = [];

afterEach(async () => {
  delete process.env[PROVENANCE_FLAG];
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function versionDoc(publisher: string, provenance: boolean): Record<string, unknown> {
  const dist: Record<string, unknown> = {};
  if (provenance) dist.attestations = { provenance: { predicateType: 'slsa' } };
  return { _npmUser: { name: publisher }, dist };
}

function packument(
  name: string,
  versions: Record<string, Record<string, unknown>>,
  time: Record<string, string>,
): Record<string, unknown> {
  return { name, versions, time, 'dist-tags': { latest: '0.0.0' } };
}

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-prov-'));
  dirs.push(dir);
  return dir;
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers });
}

async function inspect(
  packages: Array<{ name: string; version: string }>,
  packuments: Record<string, unknown>,
  opts: Partial<ProvenanceQuery> = {},
): Promise<{ hosts: string[]; calls: string[]; rows: Awaited<ReturnType<typeof provenanceFindingsForScan>>['rows']; findings: Awaited<ReturnType<typeof provenanceFindingsForScan>>['findings'] }> {
  const hosts: string[] = [];
  const calls: string[] = [];
  const cacheDir = opts.cacheDir ?? (await tempDir());
  const fetchImpl: ProvenanceQuery['fetchImpl'] = (input, init) => {
    const url = new URL(String(input));
    hosts.push(url.hostname);
    calls.push(url.toString());
    expect(init?.redirect).toBe('manual');
    const name = decodeURIComponent(url.pathname.slice(1));
    const body = packuments[name];
    if (body === undefined) return Promise.resolve(jsonResponse({}, 404));
    return Promise.resolve(jsonResponse(body));
  };
  const result = await provenanceFindingsForScan(packages, 'package-lock.json', {
    cacheDir,
    offline: false,
    now: () => NOW,
    fetchImpl,
    ...opts,
  });
  return { hosts, calls, rows: result.rows, findings: result.findings };
}

describe('phase 87 provenance signals', () => {
  it('flags provenance regression when an earlier version had dist.attestations', async () => {
    const body = packument(
      'left',
      {
        '1.0.0': versionDoc('alice', true),
        '2.0.0': versionDoc('alice', false),
      },
      { '1.0.0': AGED, '2.0.0': AGED },
    );
    const { rows, findings, hosts } = await inspect([{ name: 'left', version: '2.0.0' }], { left: body });
    expect(hosts).toEqual(['registry.npmjs.org']);
    expect(rows[0]?.data).toBe('known');
    expect(rows[0]?.signals).toEqual(['provenance-regression']);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SUPPLY-PROV-001');
    expect(findings[0]?.severity).toBe('medium');
  });

  it('flags a publisher who published none of the previous 10 versions', async () => {
    const versions: Record<string, Record<string, unknown>> = {};
    const time: Record<string, string> = {};
    for (let i = 0; i <= 11; i += 1) {
      const version = `1.0.${i}`;
      versions[version] = versionDoc(i === 0 ? 'newcomer' : 'alice', false);
      time[version] = AGED;
    }
    versions['1.0.12'] = versionDoc('newcomer', true);
    time['1.0.12'] = AGED;
    const body = packument('widened', versions, time);
    const hit = await inspect([{ name: 'widened', version: '1.0.12' }], { widened: body });
    expect(hit.rows[0]?.signals).toEqual(['publisher-change']);
    const held = await inspect([{ name: 'widened', version: '1.0.11' }], { widened: body });
    expect(held.rows[0]?.signals).toEqual([]);
    expect(held.findings).toEqual([]);
  });

  it('reuses the phase 62 age check for a new release and stays at medium', async () => {
    const versions: Record<string, Record<string, unknown>> = {};
    const time: Record<string, string> = {};
    for (let i = 0; i <= 10; i += 1) {
      const version = `1.0.${i}`;
      versions[version] = versionDoc('alice', i === 0);
      time[version] = AGED;
    }
    versions['1.0.11'] = versionDoc('newcomer', false);
    time['1.0.11'] = YOUNG;
    const body = packument('fresh', versions, time);
    const { findings, rows } = await inspect([{ name: 'fresh', version: '1.0.11' }], { fresh: body });
    expect(rows[0]?.signals).toEqual(['provenance-regression', 'publisher-change', 'new-release']);
    expect(findings).toHaveLength(1);
    expect(severityRank(findings[0]?.severity ?? 'info')).toBeLessThanOrEqual(severityRank('medium'));
    expect(`${findings[0]?.title} ${findings[0]?.message} ${findings[0]?.remediation}`).not.toMatch(/malicious/i);
    expect(findings.every((finding) => finding.ruleId !== 'DEPS-MALICIOUS-001')).toBe(true);
    const facts = releaseFactsFromCache(body, '1.0.11');
    expect(releaseAgeLabel(facts.publishedAt, NOW)).toBe('new-release');
  });

  it('does not signal an aged package that kept provenance and the same publisher', async () => {
    const body = packument(
      'steady',
      {
        '1.0.0': versionDoc('alice', true),
        '1.2.0': versionDoc('alice', true),
      },
      { '1.0.0': AGED, '1.2.0': AGED },
    );
    const { rows, findings } = await inspect([{ name: 'steady', version: '1.2.0' }], { steady: body });
    expect(rows[0]?.data).toBe('known');
    expect(rows[0]?.signals).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('contacts only registry.npmjs.org, one packument per package, and does not follow redirects', async () => {
    const cacheDir = await tempDir();
    const hosts: string[] = [];
    let calls = 0;
    const fetchImpl: ProvenanceQuery['fetchImpl'] = (input, init) => {
      calls += 1;
      const url = new URL(String(input));
      hosts.push(url.hostname);
      expect(url.protocol).toBe('https:');
      expect(init?.redirect).toBe('manual');
      if (url.pathname.includes('%40')) {
        return Promise.resolve(jsonResponse(packument('@acme/widget', { '1.0.0': versionDoc('alice', true) }, { '1.0.0': AGED })));
      }
      return Promise.resolve(new Response(null, { status: 302, headers: { location: 'https://evil.example/packument' } }));
    };
    const result = await provenanceFindingsForScan(
      [
        { name: 'left', version: '1.0.0' },
        { name: 'left', version: '2.0.0' },
        { name: '@acme/widget', version: '1.0.0' },
      ],
      'package-lock.json',
      { cacheDir, offline: false, fetchImpl, now: () => NOW },
    );
    expect(hosts).toEqual(['registry.npmjs.org', 'registry.npmjs.org']);
    expect(new Set(hosts)).toEqual(new Set(['registry.npmjs.org']));
    expect(calls).toBe(2);
    expect(result.rows.find((row) => row.name === 'left')?.data).toBe('unknown');
    expect(result.rows.find((row) => row.name === 'left')?.signals).toEqual([]);
    expect(result.findings.every((finding) => finding.ruleId === 'SUPPLY-PROV-001')).toBe(true);
  });

  it('honors Retry-After and caps concurrency at 8', async () => {
    const cacheDir = await tempDir();
    const slept: number[] = [];
    let calls = 0;
    const retryFetch: ProvenanceQuery['fetchImpl'] = () => {
      calls += 1;
      if (calls === 1) return Promise.resolve(new Response('{}', { status: 429, headers: { 'retry-after': '2' } }));
      return Promise.resolve(jsonResponse(packument('left', { '1.0.0': versionDoc('alice', true) }, { '1.0.0': AGED })));
    };
    const retried = await provenanceFindingsForScan([{ name: 'left', version: '1.0.0' }], 'package-lock.json', {
      cacheDir,
      offline: false,
      fetchImpl: retryFetch,
      sleep: (ms) => {
        slept.push(ms);
        return Promise.resolve();
      },
      now: () => NOW,
    });
    expect(slept).toEqual([2000]);
    expect(calls).toBe(2);
    expect(retried.rows[0]?.data).toBe('known');

    const names = Array.from({ length: 16 }, (_, i) => `pkg${i}`);
    let active = 0;
    let max = 0;
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pooled = provenanceFindingsForScan(
      names.map((name) => ({ name, version: '1.0.0' })),
      'package-lock.json',
      {
        cacheDir: await tempDir(),
        offline: false,
        concurrency: 32,
        now: () => NOW,
        fetchImpl: async () => {
          active += 1;
          max = Math.max(max, active);
          await gate;
          active -= 1;
          return jsonResponse(packument('pkg', { '1.0.0': versionDoc('alice', true) }, { '1.0.0': AGED }));
        },
      },
    );
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(max).toBeLessThanOrEqual(8);
    expect(max).toBe(8);
    release();
    await pooled;
    expect(max).toBeLessThanOrEqual(8);
  });

  it('uses the cache before the network and keeps the phase 62 cache shape', async () => {
    const cacheDir = await tempDir();
    const body = packument('left', { '1.0.0': versionDoc('alice', true) }, { '1.0.0': AGED });
    let calls = 0;
    const fetchImpl: ProvenanceQuery['fetchImpl'] = () => {
      calls += 1;
      return Promise.resolve(jsonResponse(body));
    };
    const opts = { cacheDir, offline: false, fetchImpl, now: () => NOW };
    await provenanceFindingsForScan([{ name: 'left', version: '1.0.0' }], 'package-lock.json', opts);
    await provenanceFindingsForScan([{ name: 'left', version: '1.0.0' }], 'package-lock.json', opts);
    expect(calls).toBe(1);
    const stored = JSON.parse(await readFile(registryCachePath(cacheDir, 'left'), 'utf8')) as { latest?: string };
    expect(stored.latest).toBe('0.0.0');
    expect(releaseFactsFromCache({ time: YOUNG, hasInstallScript: false }, '1.0.0')).toEqual({
      publishedAt: YOUNG,
      hasInstallScript: false,
    });
    expect(releaseAgeLabel(undefined, NOW)).toBe('unknown');
  });

  it('returns unknown and no signal when offline with an empty cache', async () => {
    const cacheDir = await tempDir();
    const fetchImpl: ProvenanceQuery['fetchImpl'] = () => Promise.reject(new Error('network disabled'));
    const result = await provenanceFindingsForScan([{ name: 'left', version: '1.0.0' }], 'package-lock.json', {
      cacheDir,
      offline: true,
      fetchImpl,
      now: () => NOW,
    });
    expect(result.rows).toEqual([{ name: 'left', version: '1.0.0', data: 'unknown', signals: [] }]);
    expect(result.findings).toEqual([]);
    const shorthand = await tempDir();
    const shorthandFile = registryCachePath(shorthand, 'left');
    await mkdir(dirname(shorthandFile), { recursive: true });
    await writeFile(shorthandFile, JSON.stringify({ time: YOUNG, hasInstallScript: true }));
    const partial = await provenanceFindingsForScan([{ name: 'left', version: '1.0.0' }], 'package-lock.json', {
      cacheDir: shorthand,
      offline: true,
      fetchImpl,
      now: () => NOW,
    });
    expect(partial.rows[0]?.data).toBe('unknown');
    expect(partial.findings).toEqual([]);
  });

  it('stays off unless FULLSHIELD_EXPERIMENTAL_PROVENANCE=1 and adds nothing on an empty offline cache', async () => {
    const dir = await tempDir();
    const cacheDir = await tempDir();
    await writeFile(
      join(dir, 'package-lock.json'),
      JSON.stringify({
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { 'fullshield-phase87-fixture': '2.0.0' } },
          'node_modules/fullshield-phase87-fixture': { version: '2.0.0' },
        },
      }),
    );
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'app', dependencies: { 'fullshield-phase87-fixture': '2.0.0' } }));
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ deps: { offline: true, cacheDir } }));
    const body = packument(
      'fullshield-phase87-fixture',
      { '1.0.0': versionDoc('alice', true), '2.0.0': versionDoc('alice', false) },
      { '1.0.0': AGED, '2.0.0': AGED },
    );
    const seeded = registryCachePath(cacheDir, 'fullshield-phase87-fixture');
    await mkdir(dirname(seeded), { recursive: true });
    await writeFile(seeded, JSON.stringify({ packument: body, latest: '2.0.0' }));
    const original = globalThis.fetch;
    globalThis.fetch = () => Promise.reject(new Error('network disabled'));
    try {
      const off = await scan({ cwd: dir, modules: ['deps'], offline: true });
      expect(off.findings.some((finding) => finding.ruleId === 'SUPPLY-PROV-001')).toBe(false);
      process.env[PROVENANCE_FLAG] = '1';
      const on = await scan({ cwd: dir, modules: ['deps'], offline: true });
      const hits = on.findings.filter((finding) => finding.ruleId === 'SUPPLY-PROV-001');
      expect(hits).toHaveLength(1);
      expect(hits[0]?.severity).toBe('medium');
      expect(hits[0]?.message).not.toMatch(/malicious/i);
      const empty = await tempDir();
      await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify({ deps: { offline: true, cacheDir: empty } }));
      const quiet = await scan({ cwd: dir, modules: ['deps'], offline: true });
      expect(quiet.findings.filter((finding) => finding.ruleId === 'SUPPLY-PROV-001')).toEqual([]);
      const clean = join(process.cwd(), 'test', 'fixtures', 'clean-app');
      const cleanCache = await tempDir();
      const cleanCfg = await tempDir();
      await writeFile(join(cleanCfg, 'config.json'), JSON.stringify({ deps: { offline: true, cacheDir: cleanCache } }));
      const cleanResult = await scan({ cwd: clean, configPath: join(cleanCfg, 'config.json'), offline: true });
      expect(cleanResult.findings.filter((finding) => finding.ruleId === 'SUPPLY-PROV-001')).toEqual([]);
      expect(cleanResult.findings).toEqual([]);
    } finally {
      globalThis.fetch = original;
    }
  });
});
