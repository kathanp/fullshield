import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

import { afterEach, describe, expect, it } from 'vitest';

import { hasNodeSqlite } from '../../helpers/sqlite.js';

import {
  clearRaspEvents,
  contextFromRequest,
  decideSink,
  disableRasp,
  enableRasp,
  enterRaspContext,
  hostIsBlocked,
  isPrivateOrMetadata,
  normalizeHost,
  scoreCorpusByKind,
  setSsrfLookup,
  wrapKnownPackage,
} from '../../../src/runtime/rasp/index.js';

const require = createRequire(import.meta.url);
const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures/rasp');
const attacks = JSON.parse(readFileSync(join(fixtureDir, 'attack-corpus.json'), 'utf8')) as {
  attribution?: string;
  cases: Array<Record<string, unknown>>;
};
const benign = JSON.parse(readFileSync(join(fixtureDir, 'benign-corpus.json'), 'utf8')) as {
  cases: Array<Record<string, unknown>>;
};

afterEach(() => {
  disableRasp();
  clearRaspEvents();
  setSsrfLookup(undefined);
});

describe('harden-5 SSRF host normalization', () => {
  it('strips IPv6 brackets and treats loopback / unique-local as private', () => {
    expect(normalizeHost('[::1]')).toBe('::1');
    expect(isPrivateOrMetadata('[::1]')).toBe(true);
    expect(isPrivateOrMetadata('http://not-a-host')).toBe(false);
    expect(hostIsBlocked('[fd12:3456:789a::1]')).toBe(true);
    expect(decideSink('ssrf', 'http://[::1]/', contextFromRequest({ query: { u: 'http://[::1]/' } })).block).toBe(
      true,
    );
  });

  it('handles IPv4-mapped IPv6, decimal, octal, hex, short forms, and trailing dots', () => {
    expect(hostIsBlocked('::ffff:127.0.0.1')).toBe(true);
    expect(hostIsBlocked('[::ffff:127.0.0.1]')).toBe(true);
    expect(hostIsBlocked('2130706433')).toBe(true);
    expect(hostIsBlocked('0177.0.0.1')).toBe(true);
    expect(hostIsBlocked('0x7f.0.0.1')).toBe(true);
    expect(hostIsBlocked('127.1')).toBe(true);
    expect(hostIsBlocked('127.0.0.1.')).toBe(true);
    expect(
      decideSink('ssrf', 'http://2130706433/', contextFromRequest({ query: { u: 'http://2130706433/' } })).block,
    ).toBe(true);
    expect(hostIsBlocked('8.8.8.8')).toBe(false);
  });

  it('blocks hostnames that resolve to private/loopback/metadata IPs', () => {
    setSsrfLookup((h) => (h === 'evil.internal' ? ['127.0.0.1'] : h === 'meta.internal' ? ['169.254.169.254'] : []));
    expect(hostIsBlocked('evil.internal')).toBe(true);
    expect(hostIsBlocked('meta.internal')).toBe(true);
    expect(
      decideSink(
        'ssrf',
        'http://evil.internal/latest',
        contextFromRequest({ query: { u: 'http://evil.internal/latest' } }),
      ).block,
    ).toBe(true);
    expect(
      decideSink('ssrf', 'https://example.com/api', contextFromRequest({ query: { u: 'https://example.com/api' } }))
        .block,
    ).toBe(false);
  });

  it('re-checks fetch redirect Location through a real local server', async () => {
    enableRasp({ experimental: true, mode: 'block' });
    const server = createServer((req, res) => {
      if (req.url === '/bounce') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
        return;
      }
      res.writeHead(200);
      res.end('ok');
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    const addr = server.address();
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
    const start = `http://127.0.0.1:${port}/bounce`;
    const meta = 'http://169.254.169.254/latest/meta-data/';
    try {
      await enterRaspContext(contextFromRequest({ query: { u: meta } }), async () => {
        await expect(fetch(start)).rejects.toThrow(/RASP-SSRF-001/);
      });
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    }
  });
});

describe('harden-5 public corpora', () => {
  it('reports attack block rate per category from PayloadsAllTheThings (≥95% overall)', () => {
    expect(attacks.attribution).toMatch(/PayloadsAllTheThings/);
    const result = scoreCorpusByKind(attacks.cases);
    expect(result.total).toBeGreaterThanOrEqual(80);
    for (const [kind, slot] of Object.entries(result.byKind)) {
      process.stdout.write(`  attack ${kind}: ${slot.blocked}/${slot.total}\n`);
    }
    expect(result.blocked / result.total).toBeGreaterThanOrEqual(0.95);
  });

  it('blocks none of ≥300 benign inputs (names, SQL prose, dotted files, URLs, JSON, i18n)', () => {
    const result = scoreCorpusByKind(benign.cases);
    expect(result.total).toBeGreaterThanOrEqual(300);
    for (const [kind, slot] of Object.entries(result.byKind)) {
      process.stdout.write(`  benign ${kind}: ${slot.blocked}/${slot.total}\n`);
      expect(slot.blocked).toBe(0);
    }
    expect(result.blocked).toBe(0);
  });

  it('detects genuine quote-breakout payloads in the same quoted SQL/shell contexts', () => {
    const breakouts = [
      { kind: 'sql', input: "' OR 1=1 --" },
      { kind: 'sql', input: "'; DROP TABLE x; --" },
      { kind: 'shell', input: "'; id; '" },
      { kind: 'shell', input: '"; id; "' },
    ];
    for (const want of breakouts) {
      const c = attacks.cases.find((x) => x.kind === want.kind && x.input === want.input);
      expect(c, `missing fixture ${want.kind} ${JSON.stringify(want.input)}`).toBeDefined();
      const ctx = contextFromRequest({ query: { q: want.input } });
      const hit = decideSink(want.kind as 'sql' | 'shell', c!.sink ?? c!.input, ctx).block;
      expect(hit, `${want.kind} ${JSON.stringify(want.input)} should be blocked`).toBe(true);
    }
  });
});

describe('harden-5 async request context', () => {
  it('survives await + fs/promises path escape', async () => {
    enableRasp({ experimental: true, mode: 'block' });
    const fsp = require('fs/promises') as typeof import('node:fs/promises');
    const root = mkdtempSync(join(tmpdir(), 'fullshield-rasp-h5-'));
    const uploads = join(root, 'uploads');
    mkdirSync(uploads);
    writeFileSync(join(uploads, 'ok.txt'), 'safe');
    writeFileSync(join(root, 'secret.txt'), 'nope');
    const attack = join('..', 'secret.txt');
    try {
      await enterRaspContext(contextFromRequest({ query: { q: attack } }), async () => {
        await Promise.resolve();
        await expect(async () => fsp.readFile(join(uploads, attack), 'utf8')).rejects.toThrow(/RASP-PATH-001/);
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it.skipIf(!hasNodeSqlite())('survives child_process.exec callback and spawn close', async () => {
    enableRasp({ experimental: true, mode: 'block' });
    const cp = require('child_process') as typeof import('node:child_process');
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec("CREATE TABLE users(id INTEGER, name TEXT); INSERT INTO users VALUES (1, 'ada')");
    const payload = "' OR 1=1--";
    const ctx = contextFromRequest({ query: { q: payload } });
    await enterRaspContext(ctx, () => {
      return new Promise<void>((resolve, reject) => {
        cp.exec('echo hello', (err) => {
          if (err) {
            reject(err);
            return;
          }
          try {
            expect(() => db.exec(`SELECT * FROM users WHERE name = '${payload}'`)).toThrow(/RASP-SQL-001/);
            resolve();
          } catch (e) {
            reject(e instanceof Error ? e : new Error(String(e)));
          }
        });
      });
    });
    await enterRaspContext(ctx, () => {
      return new Promise<void>((resolve, reject) => {
        const child = cp.spawn('echo hello', { shell: true });
        child.on('close', () => {
          try {
            expect(() => db.exec(`SELECT * FROM users WHERE name = '${payload}'`)).toThrow(/RASP-SQL-001/);
            resolve();
          } catch (e) {
            reject(e instanceof Error ? e : new Error(String(e)));
          }
        });
        child.on('error', reject);
      });
    });
    db.close();
  });

  it.skipIf(!hasNodeSqlite())('survives async node:sqlite after await and fetch/http.request callbacks', async () => {
    enableRasp({ experimental: true, mode: 'monitor' });
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    const http = require('node:http') as typeof import('node:http');
    const db = new DatabaseSync(':memory:');
    db.exec("CREATE TABLE users(id INTEGER, name TEXT); INSERT INTO users VALUES (1, 'ada')");
    const payload = "' OR 1=1--";
    const ctx = contextFromRequest({ query: { q: payload } });

    await enterRaspContext(ctx, async () => {
      await Promise.resolve();
      enableRasp({ experimental: true, mode: 'block' });
      expect(() => db.exec(`SELECT * FROM users WHERE name = '${payload}'`)).toThrow(/RASP-SQL-001/);
    });

    disableRasp();
    enableRasp({ experimental: true, mode: 'block' });
    const server = createServer((_req, res) => {
      res.end('ok');
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    const addr = server.address();
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
    try {
      await enterRaspContext(ctx, () => {
        return new Promise<void>((resolve, reject) => {
          http.get(`http://127.0.0.1:${port}/`, (res) => {
            res.resume();
            res.on('end', () => {
              try {
                expect(() => db.exec(`SELECT * FROM users WHERE name = '${payload}'`)).toThrow(/RASP-SQL-001/);
                resolve();
              } catch (e) {
                reject(e instanceof Error ? e : new Error(String(e)));
              }
            });
          }).on('error', reject);
        });
      });
      await enterRaspContext(ctx, async () => {
        await fetch(`http://127.0.0.1:${port}/`);
        expect(() => db.exec(`SELECT * FROM users WHERE name = '${payload}'`)).toThrow(/RASP-SQL-001/);
      });
    } finally {
      db.close();
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    }
  });
});

describe('harden-5 pg and mysql2 mocks', () => {
  it('hooks pg Client.query and mysql2 Connection.query without a real database', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const pg = {
      Client: {
        prototype: {
          query(sql: string) {
            return sql;
          },
        },
      },
    };
    const mysql2 = {
      Connection: {
        prototype: {
          query(sql: string) {
            return sql;
          },
          execute(sql: string) {
            return sql;
          },
        },
      },
    };
    wrapKnownPackage('pg', pg);
    wrapKnownPackage('mysql2', mysql2);
    const payload = "' OR 1=1--";
    expect(() =>
      enterRaspContext(contextFromRequest({ query: { q: payload } }), () => {
        pg.Client.prototype.query(`SELECT * FROM t WHERE n = '${payload}'`);
      }),
    ).toThrow(/RASP-SQL-001/);
    expect(() =>
      enterRaspContext(contextFromRequest({ query: { q: payload } }), () => {
        mysql2.Connection.prototype.query(`SELECT * FROM t WHERE n = '${payload}'`);
      }),
    ).toThrow(/RASP-SQL-001/);
    expect(() =>
      enterRaspContext(contextFromRequest({ query: { q: payload } }), () => {
        mysql2.Connection.prototype.execute(`SELECT * FROM t WHERE n = '${payload}'`);
      }),
    ).toThrow(/RASP-SQL-001/);
  });
});
