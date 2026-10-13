import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { LockedPackage } from '../../../../src/modules/deps/lockfile.js';
import { queryOsv, type FetchLike } from '../../../../src/modules/deps/osv.js';

const lodash: LockedPackage = { name: 'lodash', version: '4.17.11', path: 'node_modules/lodash' };

const lodashVuln = {
  id: 'GHSA-jf85-cpcp-j695',
  summary: 'Prototype Pollution in lodash',
  aliases: ['CVE-2019-10744'],
  database_specific: { severity: 'CRITICAL' },
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.12' }] }],
    },
  ],
};

let cacheDir: string;

beforeEach(async () => {
  cacheDir = await mkdtemp(join(tmpdir(), 'fullshield-osv-'));
});

afterEach(async () => {
  await rm(cacheDir, { recursive: true, force: true });
  vi.unstubAllGlobals();
});

function jsonResponse(body: unknown): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
}

describe('queryOsv', () => {
  it('batches queries to OSV and fetches vuln details (network mocked)', async () => {
    const fetchImpl = vi.fn<FetchLike>((input) => {
      const url = String(input);
      if (url.endsWith('/v1/querybatch')) {
        return jsonResponse({ results: [{ vulns: [{ id: lodashVuln.id, modified: '2020-01-01' }] }] });
      }
      if (url.endsWith(`/v1/vulns/${lodashVuln.id}`)) {
        return jsonResponse(lodashVuln);
      }
      return Promise.reject(new Error(`unexpected URL ${url}`));
    });

    const hits = await queryOsv([lodash], { cacheDir, offline: false, fetchImpl });

    expect(hits).toHaveLength(1);
    expect(hits[0]?.pkg.name).toBe('lodash');
    expect(hits[0]?.vulns[0]?.id).toBe(lodashVuln.id);
    expect(fetchImpl).toHaveBeenCalled();

    const cached = JSON.parse(
      await readFile(join(cacheDir, 'osv', 'lodash@4.17.11.json'), 'utf8'),
    ) as { vulns: Array<{ id: string }> };
    expect(cached.vulns[0]?.id).toBe(lodashVuln.id);
  });

  it('does not call the network in offline mode and uses the cache', async () => {
    await mkdir(join(cacheDir, 'osv'), { recursive: true });
    await writeFile(
      join(cacheDir, 'osv', 'lodash@4.17.11.json'),
      JSON.stringify({ fetchedAt: '2026-10-13T00:00:00.000Z', vulns: [lodashVuln] }),
    );
    const fetchImpl = vi.fn<FetchLike>(() =>
      Promise.reject(new Error('network should not be used offline')),
    );

    const hits = await queryOsv([lodash], { cacheDir, offline: true, fetchImpl });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(hits[0]?.vulns[0]?.id).toBe(lodashVuln.id);
  });

  it('returns no hits in offline mode when the cache is empty (does not invent vulns)', async () => {
    const fetchImpl: FetchLike = () => Promise.reject(new Error('no network'));
    const hits = await queryOsv([lodash], { cacheDir, offline: true, fetchImpl });
    expect(hits).toEqual([]);
  });

  it('refetches when the cache entry is older than 24h and the client is online', async () => {
    await mkdir(join(cacheDir, 'osv'), { recursive: true });
    await writeFile(
      join(cacheDir, 'osv', 'lodash@4.17.11.json'),
      JSON.stringify({ fetchedAt: '2020-01-01T00:00:00.000Z', vulns: [] }),
    );
    const fetchImpl = vi.fn<FetchLike>((input) => {
      const url = String(input);
      if (url.endsWith('/v1/querybatch')) {
        return jsonResponse({ results: [{ vulns: [{ id: lodashVuln.id }] }] });
      }
      return jsonResponse(lodashVuln);
    });

    const hits = await queryOsv([lodash], { cacheDir, offline: false, fetchImpl });
    expect(fetchImpl).toHaveBeenCalled();
    expect(hits[0]?.vulns[0]?.id).toBe(lodashVuln.id);
  });

  it('skips a package when the network fails rather than inventing a finding', async () => {
    const fetchImpl: FetchLike = () => Promise.reject(new Error('ENOTFOUND'));
    const hits = await queryOsv([lodash], { cacheDir, offline: false, fetchImpl });
    expect(hits).toEqual([]);
  });
});
