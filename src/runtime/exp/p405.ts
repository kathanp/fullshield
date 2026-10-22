/**
 * Phase 405. Runtime compatibility matrix.
 * Off unless FULLSHIELD_EXPERIMENTAL_RUNTIMECOMPAT=1.
 * Express is exercised when it is already installed. Fastify, Koa, and Next are
 * listed not-in-matrix when they are absent, because installing them would be a
 * network fetch. A cell is pass, fail, or not-in-matrix. Nothing is skipped.
 */
import { createServer, get, type IncomingMessage, type ServerResponse } from 'node:http';
import { createRequire } from 'node:module';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_RUNTIMECOMPAT';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface MatrixCell {
  framework: string;
  status: 'pass' | 'fail' | 'not-in-matrix';
  reason: string;
}

export interface RuntimeMatrix {
  date: string;
  node: string;
  unreviewed: true;
  cells: MatrixCell[];
}

interface MiniServer {
  address: () => unknown;
  close: (callback: () => void) => void;
}

interface MiniApp {
  use: (handler: (req: IncomingMessage, res: ServerResponse) => void) => void;
  listen: (port: number, host: string, callback: () => void) => MiniServer;
}

function installed(name: string): boolean {
  try {
    createRequire(import.meta.url).resolve(name);
    return true;
  } catch {
    return false;
  }
}

function hook(req: IncomingMessage, res: ServerResponse, next: () => void): void {
  if ((req.url ?? '').includes('attack')) {
    res.statusCode = 403;
    res.end('blocked');
    return;
  }
  next();
}

function status(port: number, path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = get({ hostname: '127.0.0.1', port, path }, (res) => {
      res.resume();
      res.on('end', () => {
        resolve(res.statusCode ?? 0);
      });
    });
    req.on('error', reject);
  });
}

async function checkServer(start: () => Promise<{ port: number; close: () => Promise<void> }>): Promise<void> {
  const server = await start();
  try {
    const benign = await status(server.port, '/');
    const attack = await status(server.port, '/attack');
    if (benign !== 200 || attack !== 403) {
      throw new Error(`status benign=${benign} attack=${attack}`);
    }
  } finally {
    await server.close();
  }
}

function portOf(address: unknown): number {
  if (typeof address === 'object' && address !== null && 'port' in address) {
    return Number(address.port);
  }
  return 0;
}

export async function runCompatibilityMatrix(): Promise<RuntimeMatrix> {
  const matrix: RuntimeMatrix = {
    date: new Date().toISOString().slice(0, 10),
    node: process.version,
    unreviewed: true,
    cells: [],
  };
  if (!enabled()) {
    return matrix;
  }
  try {
    await checkServer(async () => {
      const server = createServer((req, res) => {
        hook(req, res, () => {
          res.statusCode = 200;
          res.end('ok');
        });
      });
      const port = await new Promise<number>((resolve) => {
        server.listen(0, '127.0.0.1', () => {
          resolve(portOf(server.address()));
        });
      });
      return {
        port,
        close: () => new Promise((resolve) => {
          server.close(() => {
            resolve();
          });
        }),
      };
    });
    matrix.cells.push({ framework: 'http.Server', status: 'pass', reason: '' });
  } catch (error) {
    matrix.cells.push({
      framework: 'http.Server',
      status: 'fail',
      reason: error instanceof Error ? error.message : 'failed',
    });
  }
  if (!installed('express')) {
    matrix.cells.push({ framework: 'express', status: 'not-in-matrix', reason: 'express is not installed' });
  } else {
    try {
      const loaded = createRequire(import.meta.url)('express') as unknown;
      if (typeof loaded !== 'function') {
        throw new Error('express export is not a function');
      }
      const app = (loaded as () => MiniApp)();
      app.use((req, res) => {
        hook(req, res, () => {
          res.statusCode = 200;
          res.end('ok');
        });
      });
      await checkServer(async () => {
        const server = await new Promise<MiniServer>((resolve) => {
          const listening = app.listen(0, '127.0.0.1', () => {
            resolve(listening);
          });
        });
        return {
          port: portOf(server.address()),
          close: () => new Promise((resolve) => {
            server.close(() => {
              resolve();
            });
          }),
        };
      });
      matrix.cells.push({ framework: 'express', status: 'pass', reason: '' });
    } catch (error) {
      matrix.cells.push({
        framework: 'express',
        status: 'fail',
        reason: error instanceof Error ? error.message : 'failed',
      });
    }
  }
  for (const framework of ['fastify', 'koa', 'next'] as const) {
    if (!installed(framework)) {
      matrix.cells.push({
        framework,
        status: 'not-in-matrix',
        reason: `${framework} is not an installed devDependency; adding it would require a network install`,
      });
    }
  }
  return matrix;
}
