import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { exec } from 'node:child_process';

const require = createRequire(import.meta.url);

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  assertLocalTarget,
  buildCanary,
  confirmTarget,
  registerConfirmContainer,
  resetConfirmContainers,
} from '../../../src/confirm/index.js';

describe('Phase 20 exploit confirm (localhost only, experimental)', () => {
  it('allows localhost and 127.0.0.1 only among literals', () => {
    expect(() => assertLocalTarget('http://localhost:3000/')).not.toThrow();
    expect(() => assertLocalTarget('http://127.0.0.1:8080/user')).not.toThrow();
  });

  it('allows a FullShield-started container host after registration', () => {
    registerConfirmContainer({ id: 'fullshield-confirm-test', host: 'fs-confirm.local', ip: '172.17.0.9' });
    expect(() => assertLocalTarget('http://fs-confirm.local:80/')).not.toThrow();
    expect(() => assertLocalTarget('http://172.17.0.9:80/')).not.toThrow();
    resetConfirmContainers();
    expect(() => assertLocalTarget('http://172.17.0.9:80/')).toThrow(/refused/);
  });

  it('refuses hostnames that resolve to public IPs', () => {
    expect(() =>
      assertLocalTarget('http://evil.example/', {
        lookup: () => ['93.184.216.34'],
      }),
    ).toThrow(/refused/);
    expect(() =>
      assertLocalTarget('http://example.com/user', {
        lookup: () => ['93.184.216.34'],
      }),
    ).toThrow(/refused/);
  });

  it('refuses IPv6 forms including loopback and documentation addresses', () => {
    expect(() => assertLocalTarget('http://[::1]/')).toThrow(/refused/);
    expect(() => assertLocalTarget('http://[::ffff:127.0.0.1]/')).toThrow(/refused/);
    expect(() => assertLocalTarget('http://[2001:db8::1]/')).toThrow(/refused/);
    expect(() => assertLocalTarget('http://::1/')).toThrow(/refused/);
  });

  it('refuses encoded loopback, metadata, and other IPv4 forms', () => {
    expect(() => assertLocalTarget('http://8.8.8.8/')).toThrow(/refused/);
    expect(() => assertLocalTarget('http://2130706433/')).toThrow(/refused/);
    expect(() => assertLocalTarget('http://0177.0.0.1/')).toThrow(/refused/);
    expect(() => assertLocalTarget('http://0x7f.0.0.1/')).toThrow(/refused/);
    expect(() => assertLocalTarget('http://127.1/')).toThrow(/refused/);
    expect(() => assertLocalTarget('http://169.254.169.254/')).toThrow(/refused/);
    expect(() => assertLocalTarget('http://127.0.0.2/')).toThrow(/refused/);
  });

  it('rejects destructive canary payloads', () => {
    expect(() => buildCanary('sql', 'DROP TABLE users')).toThrow(/harmless/);
    expect(() => buildCanary('shell', 'rm -rf /')).toThrow(/harmless/);
    expect(() => buildCanary('path', '| dd if=/dev/zero')).toThrow(/harmless/);
  });

  it('is a no-op without experimental', async () => {
    const result = await confirmTarget('http://127.0.0.1:1/', { routes: [] });
    expect(result.skipped).toBe(true);
    expect(result.confirmations).toEqual([]);
  });
});

describe('Phase 20 confirmation against a local seeded app', () => {
  let base = '';
  let server: ReturnType<typeof createServer>;
  let dir = '';
  let token = '';

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'fullshield-confirm-'));
    token = 'FULLSHIELD_CANARY_deadbeef';
    writeFileSync(join(dir, 'canary.txt'), token);
    writeFileSync(join(dir, 'public.txt'), 'public');
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec('CREATE TABLE users (id INTEGER, name TEXT); INSERT INTO users VALUES (1, \'alice\'), (2, \'bob\');');
    const orders = [
      { id: '1', owner: 'alice', secret: 'alice-order' },
      { id: '2', owner: 'bob', secret: 'bob-order' },
    ];
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      if (req.method === 'GET' && url.pathname === '/user') {
        const id = url.searchParams.get('id') ?? '';
        try {
          const rows = db.prepare(`SELECT * FROM users WHERE id = ${id}`).all();
          res.end(JSON.stringify(rows));
        } catch (err) {
          res.statusCode = 500;
          res.end(String(err));
        }
        return;
      }
      if (req.method === 'GET' && url.pathname === '/file') {
        const name = url.searchParams.get('name') ?? '';
        try {
          res.end(readFileSync(join(dir, 'pub', name), 'utf8'));
        } catch {
          try {
            res.end(readFileSync(join(dir, name), 'utf8'));
          } catch (err) {
            res.statusCode = 404;
            res.end(String(err));
          }
        }
        return;
      }
      if (req.method === 'POST' && url.pathname === '/run') {
        const chunks: Buffer[] = [];
        req.on('data', (c) => chunks.push(c as Buffer));
        req.on('end', () => {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as { host?: string };
          exec(`echo ping ${body.host ?? ''}`, (err, out) => {
            res.end(out || String(err));
          });
        });
        return;
      }
      if (req.method === 'GET' && url.pathname.startsWith('/orders/')) {
        const id = url.pathname.slice('/orders/'.length);
        const user = req.headers['x-user'];
        const order = orders.find((o) => o.id === id);
        if (!order) {
          res.statusCode = 404;
          res.end('missing');
          return;
        }
        void user;
        res.end(JSON.stringify(order));
        return;
      }
      res.statusCode = 404;
      res.end('no');
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    rmSync(dir, { recursive: true, force: true });
  });

  it('confirms seeded SQLi, CMDi, path traversal, and IDOR with harmless canaries', async () => {
    const result = await confirmTarget(base, {
      experimental: true,
      canaryToken: token,
      users: { a: 'alice', b: 'bob' },
      routes: [
        { kind: 'sql', method: 'GET', path: '/user', param: 'id' },
        { kind: 'shell', method: 'POST', path: '/run', param: 'host' },
        { kind: 'path', method: 'GET', path: '/file', param: 'name' },
        { kind: 'idor', method: 'GET', path: '/orders/1', asUser: 'bob', expectOwner: 'alice' },
      ],
    });
    expect(result.skipped).toBeFalsy();
    expect(result.confirmations.find((c) => c.kind === 'sql')?.status).toBe('confirmed');
    expect(result.confirmations.find((c) => c.kind === 'shell')?.status).toBe('confirmed');
    expect(result.confirmations.find((c) => c.kind === 'path')?.status).toBe('confirmed');
    expect(result.confirmations.find((c) => c.kind === 'idor')?.status).toBe('confirmed');
    expect(result.confirmations.every((c) => c.proof?.startsWith('curl '))).toBe(true);
  });

  it('fail-opens: a down path is unconfirmed, not thrown', async () => {
    const result = await confirmTarget(base, {
      experimental: true,
      canaryToken: token,
      routes: [{ kind: 'sql', method: 'GET', path: '/missing', param: 'id' }],
    });
    expect(result.confirmations[0]?.status).toBe('unconfirmed');
  });
});
