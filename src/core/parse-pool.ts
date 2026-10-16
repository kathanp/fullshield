import { createHash } from 'node:crypto';
import { availableParallelism } from 'node:os';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';

import { packageVersion } from './version.js';

const workerUrl = new URL('./parse-worker.mjs', import.meta.url);
const cache = new Map<string, unknown>();

export function parsePoolEnabled(): boolean {
  return process.env.FULLSHIELD_PARSE_POOL === '1';
}

export function parsePoolSize(): number {
  const raw = process.env.FULLSHIELD_PARSE_WORKERS;
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1) return Math.floor(parsed);
  }
  return Math.max(1, availableParallelism() - 1);
}

export function parseCacheKey(code: string): string {
  return createHash('sha256').update(packageVersion()).update('\0').update(code).digest('hex');
}

function parseOne(code: string): Promise<unknown> {
  const key = parseCacheKey(code);
  const hit = cache.get(key);
  if (hit !== undefined) return Promise.resolve(hit);
  return new Promise((resolve, reject) => {
    const worker = new Worker(fileURLToPath(workerUrl), { workerData: { code } });
    worker.once('message', (ast: unknown) => {
      cache.set(key, ast);
      resolve(ast);
    });
    worker.once('error', reject);
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
