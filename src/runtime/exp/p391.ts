/**
 * Phase 391. Credential stuffing shape.
 * Off unless FULLSHIELD_EXPERIMENTAL_CREDSTUFF=1.
 * Process memory only. The response is this middleware's 429. No socket and no disk.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CREDSTUFF';

/** Documented defaults. High enough that a small shared-address fixture does not trip. */
export const DEFAULT_FAILURES = 20;
export const DEFAULT_USERNAMES = 8;
export const DEFAULT_WINDOW_MS = 600_000;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

interface Bucket {
  failures: number;
  users: Set<string>;
  start: number;
}

export interface StuffingResult {
  status: 200 | 429;
  event: boolean;
}

export function createStuffing(options?: {
  failures?: number;
  usernames?: number;
  windowMs?: number;
  now?: () => number;
}): (source: string, username: string, failed: boolean) => StuffingResult {
  const failures = options?.failures ?? DEFAULT_FAILURES;
  const usernames = options?.usernames ?? DEFAULT_USERNAMES;
  const windowMs = options?.windowMs ?? DEFAULT_WINDOW_MS;
  const now = options?.now ?? ((): number => Date.now());
  const buckets = new Map<string, Bucket>();
  return (source: string, username: string, failed: boolean): StuffingResult => {
    if (!enabled() || !failed) {
      return { status: 200, event: false };
    }
    const time = now();
    let bucket = buckets.get(source);
    if (bucket === undefined || time - bucket.start >= windowMs) {
      bucket = { failures: 0, users: new Set(), start: time };
      buckets.set(source, bucket);
    }
    bucket.failures += 1;
    bucket.users.add(username);
    if (bucket.failures > failures && bucket.users.size > usernames) {
      return { status: 429, event: true };
    }
    return { status: 200, event: false };
  };
}
