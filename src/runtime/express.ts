import { createInspector, type GuardOptions } from './inspect.js';

interface ExpressLikeReq {
  method?: string;
  url?: string;
  path?: string;
  ip?: string;
  query?: unknown;
  body?: unknown;
  params?: unknown;
  headers?: Record<string, unknown>;
}

interface ExpressLikeRes {
  status(code: number): { json(body: unknown): unknown };
}

/** Express middleware. Does not import the scanner. */
export function shieldGuard(options: GuardOptions = {}) {
  const inspect = createInspector(options);
  return function fullshieldGuard(
    req: ExpressLikeReq,
    res: ExpressLikeRes,
    next: (err?: unknown) => void,
  ): void {
    const result = inspect(req);
    if (result.block) {
      res.status(403).json({ error: 'blocked', ruleId: result.event?.ruleId });
      return;
    }
    next();
  };
}
