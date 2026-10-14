import { LruMap } from './lru.js';

export interface RateLimitOptions {
  windowMs: number;
  max: number;
  /** Hard cap on tracked keys (typically IP + route). Default 10_000. */
  maxKeys?: number;
}

const DEFAULT_MAX_KEYS = 10_000;

/** In-memory sliding-window limiter. Key is typically IP + route. */
export function createRateLimiter(options: RateLimitOptions) {
  const maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
  const hits = new LruMap<string, number[]>(maxKeys);
  return {
    allow(key: string, now = Date.now()): boolean {
      const windowStart = now - options.windowMs;
      const prev = (hits.get(key) ?? []).filter((t) => t > windowStart);
      if (prev.length >= options.max) {
        hits.set(key, prev);
        return false;
      }
      prev.push(now);
      hits.set(key, prev);
      return true;
    },
    get size(): number {
      return hits.size;
    },
    get maxKeys(): number {
      return maxKeys;
    },
  };
}
