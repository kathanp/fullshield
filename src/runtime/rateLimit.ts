export interface RateLimitOptions {
  windowMs: number;
  max: number;
}

/** In-memory sliding-window limiter. Key is typically IP + route. */
export function createRateLimiter(options: RateLimitOptions) {
  const hits = new Map<string, number[]>();
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
  };
}
