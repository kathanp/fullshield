import { flattenValues, inspectValues, type AttackKind } from './signatures.js';
import { createRateLimiter } from './rateLimit.js';

export type GuardMode = 'monitor' | 'block';

export interface GuardEvent {
  ruleId: string;
  path: string;
  ip: string;
  sample: string;
}

export interface GuardOptions {
  mode?: GuardMode;
  authRoutes?: string[];
  rateLimit?: { windowMs: number; max: number };
  maxBodyBytes?: number;
  maxBodyDepth?: number;
  maxBodyKeys?: number;
  onEvent?: (event: GuardEvent) => void;
  onBlock?: (event: GuardEvent) => void;
}

export interface IncomingRequest {
  method?: string;
  url?: string;
  path?: string;
  ip?: string;
  query?: unknown;
  body?: unknown;
  params?: unknown;
  headers?: Record<string, unknown>;
}

const RULE: Record<AttackKind, string> = {
  sqli: 'RUNTIME-SQLI-001',
  xss: 'RUNTIME-XSS-001',
  path: 'RUNTIME-PATH-001',
};

function bodyStats(value: unknown, depth = 0): { bytes: number; depth: number; keys: number } {
  if (value === null || value === undefined) return { bytes: 0, depth, keys: 0 };
  if (typeof value === 'string') return { bytes: value.length, depth, keys: 0 };
  if (typeof value === 'number' || typeof value === 'boolean') {
    return { bytes: String(value).length, depth, keys: 0 };
  }
  if (typeof value !== 'object') return { bytes: 0, depth, keys: 0 };
  const entries = Object.entries(value as Record<string, unknown>);
  let bytes = 2;
  let keys = entries.length;
  let maxDepth = depth;
  for (const [k, v] of entries) {
    bytes += k.length;
    const inner = bodyStats(v, depth + 1);
    bytes += inner.bytes;
    keys += inner.keys;
    if (inner.depth > maxDepth) maxDepth = inner.depth;
  }
  return { bytes, depth: maxDepth, keys };
}

export interface InspectResult {
  block: boolean;
  event?: GuardEvent;
}

export function createInspector(options: GuardOptions = {}) {
  const mode = options.mode ?? 'monitor';
  const authRoutes = new Set(options.authRoutes ?? ['/login']);
  const limiter = createRateLimiter(options.rateLimit ?? { windowMs: 60_000, max: 20 });
  const maxBodyBytes = options.maxBodyBytes ?? 1_000_000;
  const maxBodyDepth = options.maxBodyDepth ?? 8;
  const maxBodyKeys = options.maxBodyKeys ?? 200;

  return function inspect(req: IncomingRequest): InspectResult {
    const path = req.path ?? req.url?.split('?')[0] ?? '/';
    const ip = req.ip ?? 'unknown';
    const emit = (ruleId: string, sample: string, shouldBlock: boolean): InspectResult => {
      const event: GuardEvent = { ruleId, path, ip, sample: sample.slice(0, 40) };
      options.onEvent?.(event);
      if (shouldBlock) options.onBlock?.(event);
      return { block: shouldBlock, event };
    };

    if (authRoutes.has(path) && !limiter.allow(`${ip}:${path}`)) {
      return emit('RUNTIME-RATELIMIT-001', path, mode === 'block');
    }

    const stats = bodyStats(req.body);
    if (stats.bytes > maxBodyBytes || stats.depth > maxBodyDepth || stats.keys > maxBodyKeys) {
      return emit('RUNTIME-BODY-001', 'oversized-body', mode === 'block');
    }

    const values = [
      ...flattenValues(req.query),
      ...flattenValues(req.body),
      ...flattenValues(req.params),
    ];
    const kind = inspectValues(values);
    if (kind !== undefined) {
      return emit(RULE[kind], kind, mode === 'block');
    }
    return { block: false };
  };
}
