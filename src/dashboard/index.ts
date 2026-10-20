import { existsSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join } from 'node:path';

import { nodeSqliteAvailable, nodeSqliteUnavailableMessage, trackDbHandle } from '../core/sqlite.js';

const require = createRequire(import.meta.url);

export interface HistoryRow {
  scannedAt: string;
  total: number;
  highCrit: number;
}

export interface ProvenanceRow {
  scannedAt: string;
  percent: number;
  withProvenance: number;
  total: number;
}

export interface HistoryDb {
  list(): HistoryRow[];
  insert(row: HistoryRow): void;
  listProvenance(): ProvenanceRow[];
  insertProvenance(row: ProvenanceRow): void;
  close(): void;
}

function sqliteDb(file: string): HistoryDb {
  const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
  let db: InstanceType<typeof DatabaseSync> | undefined;
  try {
    db = new DatabaseSync(file);
    db.exec(
      'CREATE TABLE IF NOT EXISTS scans (scannedAt TEXT NOT NULL, total INTEGER NOT NULL, highCrit INTEGER NOT NULL)',
    );
    db.exec(
      'CREATE TABLE IF NOT EXISTS provenance (scannedAt TEXT NOT NULL, percent REAL NOT NULL, withProvenance INTEGER NOT NULL, total INTEGER NOT NULL)',
    );
  } catch (error) {
    try {
      db?.close();
    } catch {
      // never opened or already closed
    }
    throw error;
  }
  let closed = false;
  const handle = db;
  const api: HistoryDb = {
    list() {
      return handle.prepare('SELECT scannedAt, total, highCrit FROM scans ORDER BY scannedAt').all() as unknown as HistoryRow[];
    },
    insert(row) {
      handle.prepare('INSERT INTO scans (scannedAt, total, highCrit) VALUES (?, ?, ?)').run(
        row.scannedAt,
        row.total,
        row.highCrit,
      );
    },
    listProvenance() {
      return handle.prepare(
        'SELECT scannedAt, percent, withProvenance, total FROM provenance ORDER BY scannedAt',
      ).all() as unknown as ProvenanceRow[];
    },
    insertProvenance(row) {
      handle.prepare(
        'INSERT INTO provenance (scannedAt, percent, withProvenance, total) VALUES (?, ?, ?, ?)',
      ).run(row.scannedAt, row.percent, row.withProvenance, row.total);
    },
    close() {
      if (closed) return;
      closed = true;
      try {
        handle.close();
      } catch {
        // already closed
      }
    },
  };
  trackDbHandle(api);
  return api;
}

export function openHistory(dir: string): HistoryDb {
  if (!nodeSqliteAvailable()) {
    throw new Error(nodeSqliteUnavailableMessage('history'));
  }
  const root = join(dir, '.fullshield');
  mkdirSync(root, { recursive: true });
  return sqliteDb(join(root, 'history.db'));
}

export function recordHistory(db: HistoryDb, row: HistoryRow): void {
  db.insert(row);
}

export function recordProvenance(db: HistoryDb, row: ProvenanceRow): void {
  db.insertProvenance(row);
}

export function listProvenance(db: HistoryDb): ProvenanceRow[] {
  return db.listProvenance();
}

export function assertDashboardHost(host: string | undefined): boolean {
  if (host === undefined || host.length === 0) return false;
  const h = host.split(':')[0]?.toLowerCase() ?? '';
  return h === 'localhost' || h === '127.0.0.1';
}

export function createDashboardHandler(opts: {
  dbPath: string;
  experimental?: boolean;
  db?: HistoryDb;
}): (req: IncomingMessage, res: ServerResponse) => void {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM !== '1') {
    throw new Error('dashboard requires FULLSHIELD_EXPERIMENTAL_PLATFORM=1');
  }
  const db = opts.db ?? openHistory(opts.dbPath);
  return (req, res) => {
    if (!assertDashboardHost(typeof req.headers.host === 'string' ? req.headers.host : undefined)) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('invalid host');
      return;
    }
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (url.pathname === '/api/ingest' && req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST' });
      res.end('method not allowed');
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/ingest') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c as Buffer));
      req.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as HistoryRow;
          db.insert(body);
          res.writeHead(204);
          res.end();
        } catch {
          res.writeHead(400);
          res.end('bad json');
        }
      });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/history') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ scans: db.list() }));
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const scans = db.list();
      const rows = scans
        .map((s) => `<tr><td>${s.scannedAt}</td><td>${s.total}</td><td>${s.highCrit}</td></tr>`)
        .join('');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(
        `<!DOCTYPE html><html><body><h1>FullShield history</h1><table><tr><th>at</th><th>total</th><th>high+crit</th></tr>${rows}</table></body></html>`,
      );
      return;
    }
    res.writeHead(404);
    res.end('not found');
  };
}

export function startDashboard(opts: { dir: string; experimental?: boolean; port?: number }): Promise<{ close: () => Promise<void>; port: number }> {
  if (!existsSync(opts.dir)) mkdirSync(opts.dir, { recursive: true });
  const db = openHistory(opts.dir);
  const handler = createDashboardHandler({ dbPath: opts.dir, experimental: opts.experimental, db });
  const server = createServer(handler);
  return new Promise((resolve, reject) => {
    server.listen(opts.port ?? 0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      resolve({
        port,
        close: () =>
          new Promise((res, rej) => {
            server.close((err) => {
              try {
                db.close();
              } catch {
                // already closed
              }
              if (err) rej(err);
              else res();
            });
          }),
      });
    });
    server.on('error', (err) => {
      try {
        db.close();
      } catch {
        // already closed
      }
      reject(err);
    });
  });
}
