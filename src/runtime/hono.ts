import { createInspector, type GuardOptions } from './inspect.js';

interface HonoLikeContext {
  req: {
    method?: string;
    path?: string;
    url?: string;
    query?: () => unknown;
    param?: () => unknown;
    header?: (name?: string) => unknown;
    raw?: { headers?: Record<string, unknown> };
  };
  json: (body: unknown, status?: number) => unknown;
}

/** Hono middleware. Does not import the scanner. Optional peer `hono`. */
export function shieldGuard(options: GuardOptions = {}) {
  const inspect = createInspector(options);
  return async function fullshieldHono(c: HonoLikeContext, next: () => Promise<void>): Promise<unknown> {
    const headers: Record<string, unknown> = {};
    const raw = c.req.raw?.headers;
    if (raw && typeof raw === 'object') Object.assign(headers, raw);
    const result = inspect({
      method: c.req.method,
      url: c.req.url ?? c.req.path,
      path: c.req.path,
      query: typeof c.req.query === 'function' ? c.req.query() : undefined,
      params: typeof c.req.param === 'function' ? c.req.param() : undefined,
      headers,
    });
    if (result.block) {
      return c.json({ error: 'blocked', ruleId: result.event?.ruleId }, 403);
    }
    return next();
  };
}
