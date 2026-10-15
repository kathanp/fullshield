import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { shieldGuard as expressGuard } from '../../../src/runtime/express.js';
import { shieldGuard as fastifyGuard } from '../../../src/runtime/fastify.js';
import {
  clearRaspEvents,
  clearThreats,
  contextFromRequest,
  disableRasp,
  enableRasp,
  findingsToVpatches,
  honeyInit,
  isHoneyCanary,
  isIpBlocked,
  loadVirtualPatches,
  noteHoneyRouteHit,
  patchForcesBlock,
  raspContext,
  routeFromFinding,
  sinkFromRule,
  wrapKnownPackage,
} from '../../../src/runtime/rasp/index.js';
import { configureThreat } from '../../../src/runtime/rasp/threat.js';

const dirs: string[] = [];

afterEach(() => {
  disableRasp();
  clearRaspEvents();
  clearThreats();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('vpatch rule/route mapping branches', () => {
  it('maps rule ids to sinks and routes from message, file, or explicit route', () => {
    expect(sinkFromRule('SAST-SQLI-001')).toBe('sql');
    expect(sinkFromRule('RASP-SQL-001')).toBe('sql');
    expect(sinkFromRule('SAST-CMDI-001')).toBe('shell');
    expect(sinkFromRule('SHELL-INJECT')).toBe('shell');
    expect(sinkFromRule('SAST-PATH-001')).toBe('path');
    expect(sinkFromRule('RASP-NOSQL')).toBe('nosql');
    expect(sinkFromRule('SAST-SSRF-001')).toBe('ssrf');
    expect(sinkFromRule('SAST-PROTO-001')).toBe('proto');
    expect(sinkFromRule('CONFIG-HELMET-001')).toBeUndefined();

    expect(routeFromFinding({ ruleId: 'x', route: '/explicit' })).toBe('/explicit');
    expect(routeFromFinding({ ruleId: 'x', message: 'hit on /users/me' })).toBe('/users/me');
    expect(routeFromFinding({ ruleId: 'x', file: 'app/routes/login.js' })).toBe('/login');
    expect(routeFromFinding({ ruleId: 'x', file: 'app\\routes\\logout.ts' })).toBe('/logout');
    expect(routeFromFinding({ ruleId: 'x', file: 'src/index.js' })).toBeUndefined();
    expect(routeFromFinding({ ruleId: 'x' })).toBeUndefined();

    const patches = findingsToVpatches([
      { ruleId: 'SAST-SQLI-001', file: 'src/index.js' },
      { ruleId: 'SAST-PATH-001', route: '/upload' },
    ]);
    expect(patchForcesBlock(patches, '/upload', 'path')).toBe(true);
    expect(patchForcesBlock([{ ruleId: 'any' }], '/any', 'sql')).toBe(true);
    expect(patchForcesBlock([{ ruleId: 'any', route: '/only', sink: 'sql' }], '/other', 'sql')).toBe(false);
  });

  it('loadVirtualPatches accepts a raw array and missing patches', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-vpatch-load-'));
    dirs.push(dir);
    const arr = join(dir, 'arr.json');
    const empty = join(dir, 'empty.json');
    writeFileSync(arr, JSON.stringify([{ ruleId: 'SAST-SQLI-001', sink: 'sql' }]));
    writeFileSync(empty, JSON.stringify({}));
    expect(loadVirtualPatches(arr)).toEqual([expect.objectContaining({ ruleId: 'SAST-SQLI-001' })]);
    expect(loadVirtualPatches(empty)).toEqual([]);
  });
});

describe('honey + threat leftover branches', () => {
  it('resets the decoy-route window, ignores empty canary text, and appends gitignore without a trailing newline', () => {
    expect(isHoneyCanary('')).toBe(false);
    expect(noteHoneyRouteHit('203.0.113.80', 1_000)).toBe(1);
    expect(noteHoneyRouteHit('203.0.113.80', 1_100)).toBe(2);
    expect(noteHoneyRouteHit('203.0.113.80', 1_000 + 60_001)).toBe(1);

    configureThreat({ maxBlockMs: 0 });
    expect(isIpBlocked('203.0.113.81')).toBe(false);

    const dir = mkdtempSync(join(tmpdir(), 'fullshield-gi-nonewline-'));
    dirs.push(dir);
    writeFileSync(join(dir, '.gitignore'), 'keep-me', 'utf8');
    honeyInit(dir);
    const gi = readFileSync(join(dir, '.gitignore'), 'utf8');
    expect(gi.startsWith('keep-me\n')).toBe(true);
    expect(gi).toMatch(/\.env\.backup/);
  });
});

describe('raspContext remaining branches', () => {
  it('blocks a canary credential via res.status when auto-block is on', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-mw-status-'));
    dirs.push(dir);
    const canaries = honeyInit(dir);
    enableRasp({ experimental: true, mode: 'monitor', threatAutoBlock: true });
    const mw = raspContext();
    const codes: number[] = [];
    const res = {
      status(code: number) {
        codes.push(code);
        return { json() { return undefined; } };
      },
    };
    mw({ path: '/ok', ip: '203.0.113.90', query: { k: canaries.awsKey } }, res, () => undefined);
    mw({ path: '/ok', ip: '203.0.113.90', query: { k: canaries.awsKey } }, res, () => undefined);
    expect(codes).toContain(403);
  });

  it('blocks a canary credential via res.end when status() is missing', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-mw-end-'));
    dirs.push(dir);
    const canaries = honeyInit(dir);
    enableRasp({ experimental: true, mode: 'monitor', threatAutoBlock: true });
    const mw = raspContext();
    const bodies: string[] = [];
    const res: { statusCode?: number; end(body?: unknown): void } = {
      end(body?: unknown) {
        bodies.push(typeof body === 'string' ? body : JSON.stringify(body ?? ''));
      },
    };
    mw({ path: '/ok', ip: '203.0.113.91', query: { k: canaries.awsKey } }, res, () => undefined);
    mw({ path: '/ok', ip: '203.0.113.91', query: { k: canaries.awsKey } }, res, () => undefined);
    expect(res.statusCode).toBe(403);
    expect(bodies.some((b) => b.includes('blocked'))).toBe(true);
  });

  it('blocks prototype keys via res.status in block mode', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const mw = raspContext();
    const codes: number[] = [];
    const res = {
      status(code: number) {
        codes.push(code);
        return { json() { return undefined; } };
      },
    };
    mw({ path: '/', ip: '203.0.113.92', body: { constructor: true } }, res, () => undefined);
    expect(codes).toContain(403);
  });

  it('blocks prototype keys via res.end when status() is missing', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const mw = raspContext();
    const bodies: string[] = [];
    const res: { statusCode?: number; end(body?: unknown): void } = {
      end(body?: unknown) {
        bodies.push(typeof body === 'string' ? body : JSON.stringify(body ?? ''));
      },
    };
    mw({ path: '/', ip: '203.0.113.93', body: { prototype: true } }, res, () => undefined);
    expect(res.statusCode).toBe(403);
    expect(bodies.some((b) => b.includes('RASP-PROTO'))).toBe(true);
  });
});

describe('contextFromRequest branches', () => {
  it('flattens nested values, skips hop-by-hop headers, and uses url when path is missing', () => {
    const ctx = contextFromRequest({
      url: '/from-url?x=1',
      query: { n: 3, ok: true, nested: { a: ['z'] } },
      headers: { host: 'ignored', 'x-token': 'tok' },
    });
    expect(ctx.path).toBe('/from-url');
    expect(ctx.strings).toContain('3');
    expect(ctx.strings).toContain('true');
    expect(ctx.strings).toContain('z');
    expect(ctx.strings).toContain('tok');
    expect(ctx.strings).not.toContain('ignored');
  });
});

describe('wrapKnownPackage branches', () => {
  it('wraps pg/mysql2/sqlite/mongo/mongoose/axios/express and ignores primitives', () => {
    enableRasp({ experimental: true, mode: 'block' });
    expect(wrapKnownPackage('left-pad', 1)).toBe(1);
    expect(wrapKnownPackage('left-pad', null)).toBeNull();

    const pg = { Client: { prototype: { query(sql: string) { return sql; } } }, Pool: { prototype: { query(sql: string) { return sql; } } } };
    wrapKnownPackage('pg', pg);
    wrapKnownPackage('pg', pg);

    const mysql = { prototype: { query(sql: string) { return sql; }, execute(sql: string) { return sql; } } };
    wrapKnownPackage('mysql2/promise', mysql);

    const sqlite = { prototype: { exec(sql: string) { return sql; }, prepare(sql: string) { return sql; } } };
    wrapKnownPackage('better-sqlite3', sqlite);

    const mongo = { Collection: { prototype: { find(q: unknown) { return q; } } } };
    wrapKnownPackage('mongodb', mongo);

    const mongoose = { Query: { prototype: { find(q: unknown) { return q; } } } };
    wrapKnownPackage('mongoose', mongoose);

    const axios = {
      request(a: unknown) { return a; },
      get(url: string) { return url; },
      post(url: string) { return url; },
    };
    wrapKnownPackage('axios', axios);

    function express() {
      return { use() { return undefined; } };
    }
    (express as { response?: { redirect: (u: string) => string } }).response = {
      redirect(u: string) { return u; },
    };
    wrapKnownPackage('express', express);
    wrapKnownPackage('unknown-lib', { ok: true });
  });
});

describe('signature runtime guards', () => {
  it('express and fastify call next when the request is clean and 403 when blocked', () => {
    const blocked: number[] = [];
    const expressMw = expressGuard({ mode: 'block' });
    expressMw({ method: 'GET', path: '/', query: {} }, { status(code) { blocked.push(code); return { json() { return undefined; } }; } }, () => undefined);
    expect(blocked).toEqual([]);
    expressMw(
      { method: 'GET', path: '/', query: { q: "' OR 1=1--" } },
      { status(code) { blocked.push(code); return { json() { return undefined; } }; } },
      () => undefined,
    );
    expect(blocked).toContain(403);

    const fastifyCodes: number[] = [];
    const plugin = fastifyGuard({ mode: 'block' });
    plugin(
      {
        addHook(_name, hook) {
          hook(
            { method: 'GET', url: '/', query: { q: "' OR 1=1--" } },
            { code(status) { fastifyCodes.push(status); return { send() { return undefined; } }; } },
            () => undefined,
          );
          hook(
            { method: 'GET', url: '/ok', query: {} },
            { code(status) { fastifyCodes.push(status); return { send() { return undefined; } }; } },
            () => undefined,
          );
        },
      },
      {},
      () => undefined,
    );
    expect(fastifyCodes).toContain(403);
  });
});
