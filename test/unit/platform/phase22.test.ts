import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { hasNodeSqlite } from '../../helpers/sqlite.js';

import { scan } from '../../../src/core/engine.js';
import { buildThreatModel } from '../../../src/threat/index.js';
import { listWorkspaces } from '../../../src/workspaces/index.js';
import { resolveChangedFiles } from '../../../src/incremental/index.js';
import {
  assertDashboardHost,
  createDashboardHandler,
  openHistory,
  recordHistory,
} from '../../../src/dashboard/index.js';

const vuln = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const dirs: string[] = [];

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('Phase 22 threat model (experimental)', () => {
  it('is a no-op without experimental', () => {
    const model = buildThreatModel(vuln);
    expect(model.skipped).toBe(true);
  });

  it('builds a STRIDE table and Mermaid map from Express routes', () => {
    const model = buildThreatModel(vuln, { experimental: true });
    expect(model.skipped).toBeFalsy();
    expect(model.routes.some((r) => r.path === '/user')).toBe(true);
    expect(model.stride.length).toBeGreaterThan(0);
    expect(model.mermaid).toMatch(/flowchart/);
  });
});

describe('Phase 22 incremental + workspaces', () => {
  it('resolveChangedFiles is empty without experimental', () => {
    expect(resolveChangedFiles(vuln, { changed: true })).toEqual([]);
  });

  it('restricts a --changed scan to the listed files', async () => {
    const t0 = performance.now();
    const result = await scan({
      cwd: vuln,
      modules: ['sast'],
      offline: true,
      changed: true,
      experimentalIncremental: true,
      changedFiles: ['src/index.js'],
    });
    expect(performance.now() - t0).toBeLessThan(5000);
    expect(result.metadata.filesScanned).toBeGreaterThan(0);
    expect(result.findings.some((f) => f.ruleId === 'SAST-SQLI-001')).toBe(true);
  });

  it('lists npm workspaces from package.json', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-ws-'));
    dirs.push(dir);
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ workspaces: ['packages/a', 'packages/b'] }),
    );
    mkdirSync(join(dir, 'packages', 'a'), { recursive: true });
    mkdirSync(join(dir, 'packages', 'b'), { recursive: true });
    expect(listWorkspaces(dir, { experimental: true })).toEqual(['packages/a', 'packages/b']);
    expect(listWorkspaces(dir)).toEqual([]);
  });

  it('reads workspaces.packages, pnpm-workspace.yaml, and empty/invalid manifests', () => {
    expect(listWorkspaces('/no/such/fullshield-ws', { experimental: true })).toEqual([]);

    const empty = mkdtempSync(join(tmpdir(), 'fullshield-ws-empty-'));
    dirs.push(empty);
    expect(listWorkspaces(empty, { experimental: true })).toEqual([]);

    const bad = mkdtempSync(join(tmpdir(), 'fullshield-ws-bad-'));
    dirs.push(bad);
    writeFileSync(join(bad, 'package.json'), '{not json');
    expect(listWorkspaces(bad, { experimental: true })).toEqual([]);

    const obj = mkdtempSync(join(tmpdir(), 'fullshield-ws-obj-'));
    dirs.push(obj);
    writeFileSync(join(obj, 'package.json'), JSON.stringify({ workspaces: { packages: ['apps/*'] } }));
    expect(listWorkspaces(obj, { experimental: true })).toEqual(['apps/*']);

    const pnpm = mkdtempSync(join(tmpdir(), 'fullshield-ws-pnpm-'));
    dirs.push(pnpm);
    writeFileSync(join(pnpm, 'package.json'), JSON.stringify({ name: 'root' }));
    writeFileSync(join(pnpm, 'pnpm-workspace.yaml'), 'packages:\n- packages/*\n- apps/*\n');
    expect(listWorkspaces(pnpm, { experimental: true })).toEqual(['packages/*', 'apps/*']);

    expect(resolveChangedFiles(vuln, { experimental: true })).toEqual([]);
    expect(
      resolveChangedFiles(vuln, {
        experimental: true,
        since: 'HEAD',
        git: () => 'src/a.js\n\nsrc/b.js\n',
      }),
    ).toEqual(['src/a.js', 'src/b.js']);
    expect(
      resolveChangedFiles(vuln, {
        experimental: true,
        changed: true,
        git: () => 'staged.js\n',
      }),
    ).toEqual(['staged.js']);
  });
});

describe('Phase 22 dashboard (127.0.0.1 + Host lock)', () => {
  it('accepts only localhost / 127.0.0.1 Host headers', () => {
    expect(assertDashboardHost('127.0.0.1')).toBe(true);
    expect(assertDashboardHost('localhost')).toBe(true);
    expect(assertDashboardHost('127.0.0.1:7432')).toBe(true);
    expect(assertDashboardHost('localhost:7432')).toBe(true);
    expect(assertDashboardHost('evil.example')).toBe(false);
    expect(assertDashboardHost('example.com')).toBe(false);
    expect(assertDashboardHost('[::1]')).toBe(false);
  });

  it.skipIf(!hasNodeSqlite())('GET pages do not mutate history; Host rebinding is rejected; bind is loopback', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-dash-'));
    dirs.push(dir);
    const db = openHistory(dir);
    recordHistory(db, { scannedAt: '2026-10-14T00:00:00Z', total: 2, highCrit: 1 });
    const handler = createDashboardHandler({ dbPath: dir, experimental: true, db });
    const server = createServer(handler);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    try {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      expect(typeof addr === 'object' && addr !== null && addr.address === '127.0.0.1').toBe(true);
      const get = (path: string, host: string, method = 'GET') =>
        new Promise<{ status: number; text: string }>((resolve, reject) => {
          const req = httpRequest(
            { host: '127.0.0.1', port, path, method, headers: { host } },
            (res) => {
              const chunks: Buffer[] = [];
              res.on('data', (c) => chunks.push(c as Buffer));
              res.on('end', () =>
                resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') }),
              );
            },
          );
          req.on('error', reject);
          req.end();
        });
      const ok = await get('/', '127.0.0.1');
      expect(ok.status).toBe(200);
      expect(ok.text).toMatch(/2/);
      const rebound = await get('/', 'evil.example');
      expect(rebound.status).toBe(400);
      const mutateGet = await get('/api/ingest', '127.0.0.1', 'GET');
      expect(mutateGet.status).toBe(405);
      const after = await get('/api/history', 'localhost');
      expect(after.status).toBe(200);
      const parsed = JSON.parse(after.text) as { scans: unknown[] };
      expect(parsed.scans).toHaveLength(1);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      db.close();
    }
  });

  it.skipIf(!hasNodeSqlite())('close() releases history.db so the directory can be removed', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-dash-close-'));
    dirs.push(dir);
    const db = openHistory(dir);
    recordHistory(db, { scannedAt: '2026-10-14T00:00:00Z', total: 1, highCrit: 0 });
    db.close();
    expect(() => rmSync(join(dir, '.fullshield'), { recursive: true, force: true })).not.toThrow();
  });

  it.skipIf(!hasNodeSqlite())('close() is idempotent and still releases the handle', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-dash-err-'));
    dirs.push(dir);
    const db = openHistory(dir);
    recordHistory(db, { scannedAt: '2026-10-14T00:00:00Z', total: 1, highCrit: 0 });
    db.close();
    db.close();
    expect(() => rmSync(join(dir, '.fullshield'), { recursive: true, force: true })).not.toThrow();
  });

  it('is a no-op without experimental', () => {
    expect(() => createDashboardHandler({ dbPath: '/tmp', experimental: false })).toThrow(/EXPERIMENTAL/i);
  });
});
