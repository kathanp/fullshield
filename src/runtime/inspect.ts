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
  /** Statistical anomaly baseline (spec §16.4). No LLM. */
  anomaly?: {
    learnMinutes: number;
    now?: () => number;
    onAnomaly?: (event: GuardEvent) => void;
  };
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
  statusCode?: number;
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

interface RouteBaseline {
  count: number;
  bodySum: number;
  paramNames: Set<string>;
  status401: number;
  status404: number;
  recent404: number;
}

function keysOf(value: unknown): string[] {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  return Object.keys(value);
}

export function createInspector(options: GuardOptions = {}) {
  const mode = options.mode ?? 'monitor';
  const authRoutes = new Set(options.authRoutes ?? ['/login']);
  const limiter = createRateLimiter(options.rateLimit ?? { windowMs: 60_000, max: 20 });
  const maxBodyBytes = options.maxBodyBytes ?? 1_000_000;
  const maxBodyDepth = options.maxBodyDepth ?? 8;
  const maxBodyKeys = options.maxBodyKeys ?? 200;
  const anomaly = options.anomaly;
  const routes = new Map<string, RouteBaseline>();
  let windowStart: number | undefined;

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

    if (anomaly !== undefined) {
      const now = anomaly.now ?? Date.now;
      const t = now();
      if (windowStart === undefined) windowStart = t;
      const learning = t - windowStart < anomaly.learnMinutes * 60_000;
      let baseline = routes.get(path);
      if (baseline === undefined) {
        baseline = { count: 0, bodySum: 0, paramNames: new Set(), status401: 0, status404: 0, recent404: 0 };
        routes.set(path, baseline);
      }
      const names = [...keysOf(req.query), ...keysOf(req.body), ...keysOf(req.params)];
      const status = req.statusCode;
      if (learning) {
        baseline.count += 1;
        baseline.bodySum += stats.bytes;
        for (const n of names) baseline.paramNames.add(n);
        if (status === 401) baseline.status401 += 1;
        if (status === 404) baseline.status404 += 1;
      } else {
        const newParam = names.some((n) => !baseline.paramNames.has(n));
        const spike401 = status === 401 && baseline.status401 === 0 && baseline.count > 0;
        if (status === 404) baseline.recent404 += 1;
        else baseline.recent404 = 0;
        const burst404 = baseline.recent404 >= 3 && baseline.status404 === 0 && baseline.count > 0;
        if (newParam || spike401 || burst404) {
          const event: GuardEvent = {
            ruleId: 'RUNTIME-ANOMALY-001',
            path,
            ip,
            sample: newParam ? 'new-param' : spike401 ? '401-spike' : '404-burst',
          };
          anomaly.onAnomaly?.(event);
          options.onEvent?.(event);
          return { block: false, event };
        }
      }
    }

    return { block: false };
  };
}
