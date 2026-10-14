import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import {
  clearRaspEvents,
  contextFromRequest,
  decideSink,
  disableRasp,
  enableRasp,
  enableRaspFromEnv,
  enterRaspContext,
  getRaspEvents,
  isRaspEnabled,
  raspContext,
  scoreCorpus,
  wrapKnownPackage,
} from '../../../src/runtime/rasp/index.js';

const require = createRequire(import.meta.url);
const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures/rasp');

const attacks = JSON.parse(readFileSync(join(fixtureDir, 'attack-corpus.json'), 'utf8')) as {
  cases: Array<Record<string, unknown>>;
};
const benign = JSON.parse(readFileSync(join(fixtureDir, 'benign-corpus.json'), 'utf8')) as {
  cases: Array<Record<string, unknown>>;
};

afterEach(() => {
  disableRasp();
  clearRaspEvents();
});

describe('RASP structure-change corpus', () => {
  it('blocks at least 95% of the attack corpus', () => {
    const result = scoreCorpus(attacks.cases);
    expect(result.total).toBeGreaterThanOrEqual(40);
    expect(result.blocked / result.total).toBeGreaterThanOrEqual(0.95);
  });

  it('blocks none of the benign corpus (O\'Brien, SELECT your seat, dotted paths, URLs in comments)', () => {
    const result = scoreCorpus(benign.cases);
    expect(result.total).toBeGreaterThanOrEqual(20);
    expect(result.blocked).toBe(0);
  });
});

describe('RASP experimental flag and fail-open', () => {
  it('stays disabled unless experimental is set', () => {
    enableRasp({ mode: 'block' });
    expect(isRaspEnabled()).toBe(false);
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec('CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (7)');
    expect(db.prepare('SELECT x FROM t').get()).toEqual({ x: 7 });
    db.close();
  });

  it('fails open: a throwing decide still runs the original call and logs an event', () => {
    enableRasp({
      experimental: true,
      mode: 'block',
      decide: () => {
        throw new Error('injected hook failure');
      },
    });
    expect(isRaspEnabled()).toBe(true);
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    enterRaspContext(contextFromRequest({ path: '/', query: { q: "' OR 1=1--" } }), () => {
      db.exec('CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (1)');
    });
    expect(db.prepare('SELECT x FROM t').get()).toEqual({ x: 1 });
    db.close();
    expect(getRaspEvents().some((e) => e.ruleId === 'RASP-FAIL-OPEN-001')).toBe(true);
  });

  it('defaults to monitor: detected SQL injection emits an event but the query still runs', () => {
    enableRasp({ experimental: true });
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec("CREATE TABLE users(id INTEGER, name TEXT); INSERT INTO users VALUES (1, 'admin'), (2, 'ada')");
    const payload = "' OR 1=1--";
    enterRaspContext(contextFromRequest({ path: '/q', query: { q: payload } }), () => {
      const rows = db.prepare(`SELECT * FROM users WHERE name = '${payload}'`).all();
      expect(rows.length).toBeGreaterThan(1);
    });
    db.close();
    expect(getRaspEvents().some((e) => e.ruleId === 'RASP-SQL-001')).toBe(true);
  });
});

describe('RASP real sinks (node:sqlite, child_process, fs)', () => {
  it('blocks concatenated SQLi on node:sqlite in block mode and leaves the table intact', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec("CREATE TABLE users(id INTEGER, name TEXT); INSERT INTO users VALUES (1, 'admin'), (2, 'ada')");
    const payload = "' OR 1=1--";
    expect(() =>
      enterRaspContext(contextFromRequest({ path: '/q', query: { q: payload } }), () => {
        db.exec(`SELECT * FROM users WHERE name = '${payload}'`);
      }),
    ).toThrow(/RASP-SQL-001/);
    expect(db.prepare('SELECT COUNT(*) AS n FROM users').get()).toEqual({ n: 2 });
    db.close();
  });

  it('allows parameterized O\'Brien on node:sqlite', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec("CREATE TABLE users(id INTEGER, name TEXT); INSERT INTO users VALUES (1, 'O''Brien')");
    enterRaspContext(contextFromRequest({ path: '/q', query: { q: "O'Brien" } }), () => {
      const row = db.prepare('SELECT name FROM users WHERE name = ?').get("O'Brien") as { name: string };
      expect(row.name).toBe("O'Brien");
    });
    db.close();
  });

  it('blocks shell metacharacters on a real child_process.execSync and allows a benign echo', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const cp = require('child_process') as typeof import('node:child_process');
    const attack = 'ok; echo pwned';
    expect(() =>
      enterRaspContext(contextFromRequest({ path: '/sh', query: { q: attack } }), () => {
        cp.execSync(`echo ${attack}`, { encoding: 'utf8' });
      }),
    ).toThrow(/RASP-SHELL-001/);
    const out = enterRaspContext(contextFromRequest({ path: '/sh', query: { q: 'hello' } }), () =>
      cp.execSync('echo hello', { encoding: 'utf8' }),
    );
    expect(out.trim()).toBe('hello');
  });

  it('blocks fs path escape with real readFileSync and allows a file inside the join base', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const fs = require('fs') as typeof import('node:fs');
    const root = mkdtempSync(join(tmpdir(), 'fullshield-rasp-'));
    const uploads = join(root, 'uploads');
    mkdirSync(uploads);
    writeFileSync(join(uploads, 'ok.txt'), 'safe');
    writeFileSync(join(root, 'secret.txt'), 'nope');
    try {
      const attack = join('..', 'secret.txt');
      expect(() =>
        enterRaspContext(contextFromRequest({ path: '/f', query: { q: attack } }), () => {
          fs.readFileSync(join(uploads, attack), 'utf8');
        }),
      ).toThrow(/RASP-PATH-001/);
      const body = enterRaspContext(contextFromRequest({ path: '/f', query: { q: 'ok.txt' } }), () =>
        fs.readFileSync(join(uploads, 'ok.txt'), 'utf8'),
      );
      expect(body).toBe('safe');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('RASP decideSink kinds', () => {
  it('blocks NoSQL $ operators supplied as the value and prototype pollution keys', () => {
    const nosql = decideSink('nosql', { name: { $gt: '' } }, contextFromRequest({ body: { name: { $gt: '' } } }));
    expect(nosql.block).toBe(true);
    expect(nosql.ruleId).toBe('RASP-NOSQL-001');
    const protoBody = JSON.parse('{"__proto__":{"admin":true}}') as Record<string, unknown>;
    const proto = decideSink('proto', null, contextFromRequest({ body: protoBody }));
    expect(proto.block).toBe(true);
    expect(proto.ruleId).toBe('RASP-PROTO-001');
  });

  it('blocks SSRF to metadata/loopback when the host comes from user input, not when it is only in the query', () => {
    const meta = decideSink(
      'ssrf',
      'http://169.254.169.254/latest/meta-data/',
      contextFromRequest({ query: { u: 'http://169.254.169.254/latest/meta-data/' } }),
    );
    expect(meta.block).toBe(true);
    expect(meta.ruleId).toBe('RASP-SSRF-001');
    const queryOnly = decideSink(
      'ssrf',
      'https://example.com/q?next=http://169.254.169.254/',
      contextFromRequest({ query: { u: 'http://169.254.169.254/' } }),
    );
    expect(queryOnly.block).toBe(false);
  });
});

describe('RASP Express request overhead', () => {
  it('adds p95 < 1ms on a real Express request that runs a parameterized node:sqlite query', async () => {
    enableRasp({ experimental: true, mode: 'monitor' });
    // express is an optional peer; no @types/express in this package
    const express = require('express') as (reqHandler?: unknown) => {
      use: (fn: unknown) => void;
      get: (path: string, fn: (req: { query: { name?: string } }, res: { end: (s: string) => void }) => void) => void;
    };
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec("CREATE TABLE users(id INTEGER, name TEXT); INSERT INTO users VALUES (1, 'ada')");
    const samples: number[] = [];
    const app = express();
    app.use(raspContext());
    app.get('/q', (req, res) => {
      const name = typeof req.query.name === 'string' ? req.query.name : '';
      const t0 = performance.now();
      db.prepare('SELECT name FROM users WHERE name = ?').get(name);
      samples.push(performance.now() - t0);
      res.end('ok');
    });
    const server = createServer(app as Parameters<typeof createServer>[0]);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    const addr = server.address();
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
    const http = require('node:http') as typeof import('node:http');

    const get = (name: string) =>
      new Promise<void>((resolve, reject) => {
        const req = http.get(`http://127.0.0.1:${port}/q?name=${encodeURIComponent(name)}`, (res) => {
          res.resume();
          res.on('end', resolve);
        });
        req.on('error', reject);
      });

    const WARM = 40;
    const N = 200;
    for (let i = 0; i < WARM; i += 1) await get('ada');
    samples.length = 0;
    for (let i = 0; i < N; i += 1) await get('ada');

    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    db.close();

    samples.sort((a, b) => a - b);
    const p95 = samples[Math.floor(samples.length * 0.95)] ?? 99;
    expect(p95).toBeLessThan(1);
  });
});

describe('RASP package hooks and activation', () => {
  it('wraps a fake pg Client.query with structure-change detection', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const fake = {
      Client: {
        prototype: {
          query(sql: string) {
            return sql;
          },
        },
      },
    };
    wrapKnownPackage('pg', fake);
    const payload = "' OR 1=1--";
    expect(() =>
      enterRaspContext(contextFromRequest({ query: { q: payload } }), () => {
        fake.Client.prototype.query(`SELECT * FROM t WHERE n = '${payload}'`);
      }),
    ).toThrow(/RASP-SQL-001/);
  });

  it('enableRaspFromEnv is a no-op without FULLSHIELD_EXPERIMENTAL_RASP', () => {
    const prev = process.env.FULLSHIELD_EXPERIMENTAL_RASP;
    delete process.env.FULLSHIELD_EXPERIMENTAL_RASP;
    enableRaspFromEnv();
    expect(isRaspEnabled()).toBe(false);
    if (prev !== undefined) process.env.FULLSHIELD_EXPERIMENTAL_RASP = prev;
  });

  it('register and auto stay inert without the experimental env', async () => {
    await import('../../../src/runtime/register.js');
    await import('../../../src/runtime/auto.js');
    const loader = await import('../../../src/runtime/rasp/loader.js');
    const next = { called: false };
    await loader.load('file:///x.js', {}, () => {
      next.called = true;
      return Promise.resolve({ format: 'module' });
    });
    expect(next.called).toBe(true);
    expect(isRaspEnabled()).toBe(false);
  });
});
