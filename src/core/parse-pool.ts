import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { availableParallelism, homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';

import { LruMap } from '../runtime/lru.js';
import { perf2Enabled } from './perf2.js';
import { packageVersion } from './version.js';

const workerUrl = new URL('./parse-worker.mjs', import.meta.url);
const memory = new LruMap<string, unknown>(64);

export function parsePoolEnabled(): boolean {
  return perf2Enabled() || process.env.FULLSHIELD_PARSE_POOL === '1';
}

/** Default `max(1, CPUs − 1)`. `FULLSHIELD_PARSE_WORKERS` is a positive integer cap. */
export function parsePoolSize(): number {
  const cores = Math.max(1, availableParallelism() - 1);
  const raw = process.env.FULLSHIELD_PARSE_WORKERS;
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1) {return Math.min(cores, Math.floor(parsed));}
  }
  return cores;
}

function workerMemoryMb(): number {
  const raw = process.env.FULLSHIELD_PARSE_WORKER_MB;
  const parsed = raw !== undefined && raw !== '' ? Number(raw) : 512;
  if (Number.isFinite(parsed) && parsed >= 64) {return Math.floor(parsed);}
  return 512;
}

/** On-disk parse cache. Taint summaries live in a subdirectory of this path. */
export function parseCacheDir(): string {
  return process.env.FULLSHIELD_PARSE_CACHE_DIR ?? join(homedir(), '.cache', 'fullshield', 'parse');
}

export function parseCacheKey(code: string): string {
  return createHash('sha256').update(packageVersion()).update('\0').update(code).digest('hex');
}

function diskPath(key: string): string {
  return join(parseCacheDir(), 'ast', key.slice(0, 2), `${key}.json`);
}

async function readDisk(key: string): Promise<{ ast: unknown } | undefined> {
  if (!perf2Enabled()) {return undefined;}
  try {
    const text = await readFile(diskPath(key), 'utf8');
    return { ast: JSON.parse(text) as unknown };
  } catch {
    return undefined;
  }
}

async function writeDisk(key: string, ast: unknown): Promise<void> {
  if (!perf2Enabled() || ast === undefined || ast === null) {return;}
  try {
    const path = diskPath(key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, JSON.stringify(ast), 'utf8');
  } catch {
    // Cache write is best-effort.
  }
}

function parseOnWorker(code: string): Promise<unknown> {
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
      if (settled) {return;}
      settled = true;
      finish();
      resolve(ast);
    };
    const fail = (error: Error): void => {
      if (settled) {return;}
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
    worker.once('exit', (code) => {
      if (settled) {return;}
      fail(new Error(`parse worker exited ${code ?? 'null'}`));
    });
  });
}

async function parseOne(code: string): Promise<unknown> {
  const key = parseCacheKey(code);
  const hit = memory.get(key);
  if (hit !== undefined) {return hit;}
  const disk = await readDisk(key);
  if (disk !== undefined) {
    memory.set(key, disk.ast);
    return disk.ast;
  }
  const ast = await parseOnWorker(code);
  memory.set(key, ast);
  await writeDisk(key, ast);
  return ast;
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
      if (index >= codes.length) {return;}
      const code = codes[index];
      if (code === undefined) {return;}
      out[index] = await parseOne(code);
    }
  }
  const workers = Math.min(size, Math.max(1, codes.length));
  await Promise.all(Array.from({ length: workers }, () => run()));
  return out;
}
