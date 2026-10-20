import { applyDlpWrite, createDlpInspector } from './dlp/index.js';
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
  statusCode?: number;
  json?(body: unknown): unknown;
  send?(body: unknown): unknown;
  getHeader?(name: string): unknown;
}

function attachExpressDlp(
  req: ExpressLikeReq,
  res: ExpressLikeRes,
  dlp: NonNullable<ReturnType<typeof createDlpInspector>>,
): void {
  const path = req.path ?? req.url?.split('?')[0] ?? '/';
  const ip = req.ip ?? 'unknown';
  const origJson = res.json?.bind(res);
  const origSend = res.send?.bind(res);
  let busy = false;
  const run = (body: unknown, write: (b: unknown) => unknown): unknown => {
    if (busy) {return write(body);}
    busy = true;
    try {
      const ct = res.getHeader?.('content-type');
      const out = applyDlpWrite(dlp, body, { path, ip, contentType: typeof ct === 'string' ? ct : undefined });
      if (out.block) {
        return res.status(500).json({ error: 'internal error' });
      }
      return write(out.body);
    } finally {
      busy = false;
    }
  };
  if (origJson) {res.json = (body: unknown) => run(body, origJson);}
  if (origSend) {res.send = (body: unknown) => run(body, origSend);}
}

/** Express middleware. Does not import the scanner. */
export function shieldGuard(options: GuardOptions = {}) {
  const inspect = createInspector(options);
  const dlp = createDlpInspector(options);
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
    if (dlp !== undefined) {attachExpressDlp(req, res, dlp);}
    next();
  };
}
