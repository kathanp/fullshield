import { applyDlpWrite, createDlpInspector } from './dlp/index.js';
import { createInspector, type GuardOptions } from './inspect.js';

interface KoaLikeCtx {
  method?: string;
  url?: string;
  path?: string;
  ip?: string;
  query?: unknown;
  request?: { body?: unknown };
  params?: unknown;
  headers?: Record<string, unknown>;
  status: number;
  body: unknown;
}

/** Koa middleware. Does not import the scanner. Optional peer `koa`. */
export function shieldGuard(options: GuardOptions = {}) {
  const inspect = createInspector(options);
  const dlp = createDlpInspector(options);
  return async function fullshieldKoa(ctx: KoaLikeCtx, next: () => Promise<void>): Promise<void> {
    const result = inspect({
      method: ctx.method,
      url: ctx.url,
      path: ctx.path ?? ctx.url?.split('?')[0],
      ip: ctx.ip,
      query: ctx.query,
      body: ctx.request?.body,
      params: ctx.params,
      headers: ctx.headers,
    });
    if (result.block) {
      ctx.status = 403;
      ctx.body = { error: 'blocked', ruleId: result.event?.ruleId };
      return;
    }
    await next();
    if (dlp === undefined) return;
    const out = applyDlpWrite(dlp, ctx.body, { path: ctx.path ?? ctx.url?.split('?')[0] ?? '/', ip: ctx.ip });
    if (out.block) {
      ctx.status = 500;
      ctx.body = { error: 'internal error' };
      return;
    }
    ctx.body = out.body;
  };
}
