import { createHash } from 'node:crypto';
import { availableParallelism } from 'node:os';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';

import { LruMap } from '../runtime/lru.js';
import { packageVersion } from './version.js';

const workerUrl = new URL('./parse-worker.mjs', import.meta.url);
const cache = new LruMap<string, unknown>(64);

export function parsePoolEnabled(): boolean {
  return process.env.FULLSHIELD_PARSE_POOL === '1';
}

/** Explicit `FULLSHIELD_PARSE_WORKERS` is capped at 4. The default is at most 2. */
export function parsePoolSize(): number {
  const raw = process.env.FULLSHIELD_PARSE_WORKERS;
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1) return Math.min(4, Math.floor(parsed));
  }
  return Math.min(2, Math.max(1, availableParallelism() - 1));
}

function workerMemoryMb(): number {
  const raw = process.env.FULLSHIELD_PARSE_WORKER_MB;
  const parsed = raw !== undefined && raw !== '' ? Number(raw) : 512;
  if (Number.isFinite(parsed) && parsed >= 64) return Math.floor(parsed);
  return 512;
}

export function parseCacheKey(code: string): string {
  return createHash('sha256').update(packageVersion()).update('\0').update(code).digest('hex');
}

function parseOne(code: string): Promise<unknown> {
  const key = parseCacheKey(code);
  const hit = cache.get(key);
  if (hit !== undefined) return Promise.resolve(hit);
  return new Promise((resolve, reject) => {
    const worker = new Worker(fileURLToPath(workerUrl), {
      workerData: { code },
      resourceLimits: { maxOldGenerationSizeMb: workerMemoryMb() },
    });
    let settled = false;
    const finish = (): void => {
      void worker.terminate();
    };
    const succeed = (ast: unknown): void => {
      if (settled) return;
      settled = true;
      cache.set(key, ast);
      finish();
      resolve(ast);
    };
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      finish();
      reject(error);
    };
    worker.once('message', (ast: unknown) => {
      succeed(ast);
    });
    worker.once('error', (error: Error) => {
      fail(error);
    });
    // terminate() after a message also emits exit. Ignore that one.
    worker.once('exit', (code) => {
      if (settled) return;
      fail(new Error(`parse worker exited ${code ?? 'null'}`));
    });
  });
}

/** Parse sources on a worker pool. Results are cached by content hash and FullShield version. */
export async function parseWithPool(codes: readonly string[]): Promise<unknown[]> {
  const size = parsePoolSize();
  const out: unknown[] = new Array(codes.length);
  let next = 0;
  async function run(): Promise<void> {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= codes.length) return;
      const code = codes[index];
      if (code === undefined) return;
      out[index] = await parseOne(code);
    }
  }
  const workers = Math.min(size, Math.max(1, codes.length));
  await Promise.all(Array.from({ length: workers }, () => run()));
  return out;
}
