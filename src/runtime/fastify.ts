import { applyDlpWrite, createDlpInspector } from './dlp/index.js';
import { createInspector, type GuardOptions } from './inspect.js';

interface FastifyReq {
  method?: string;
  url?: string;
  ip?: string;
  query?: unknown;
  body?: unknown;
  params?: unknown;
  headers?: Record<string, unknown>;
}

interface FastifyReply {
  code(status: number): { send(body: unknown): unknown };
}

interface FastifyLike {
  addHook(
    name: string,
    hook: (
      req: FastifyReq,
      reply: FastifyReply,
      payloadOrDone?: unknown,
      done?: (err?: unknown, payload?: unknown) => void,
    ) => void,
  ): void;
}

/** Fastify plugin. Does not import the scanner. */
export function shieldGuard(options: GuardOptions = {}) {
  const inspect = createInspector(options);
  const dlp = createDlpInspector(options);
  return function fullshieldFastify(instance: FastifyLike, _opts: unknown, done: (err?: Error) => void): void {
    instance.addHook('preHandler', (req, reply, next) => {
      const result = inspect({
        method: req.method,
        url: req.url,
        path: req.url?.split('?')[0],
        ip: req.ip,
        query: req.query,
        body: req.body,
        params: req.params,
        headers: req.headers,
      });
      if (result.block) {
        reply.code(403).send({ error: 'blocked', ruleId: result.event?.ruleId });
        return;
      }
      (next as (err?: unknown) => void)();
    });
    if (dlp !== undefined) {
      instance.addHook('onSend', (req, reply, payload, sendDone) => {
        const path = req.url?.split('?')[0] ?? '/';
        const out = applyDlpWrite(dlp, payload, { path, ip: req.ip });
        if (out.block) {
          reply.code(500);
          sendDone?.(null, JSON.stringify({ error: 'internal error' }));
          return;
        }
        sendDone?.(null, typeof out.body === 'string' ? out.body : JSON.stringify(out.body));
      });
    }
    done();
  };
}
