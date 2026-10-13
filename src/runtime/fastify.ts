import { createInspector, type GuardOptions } from './inspect.js';

interface FastifyLike {
  addHook(
    name: 'preHandler',
    hook: (
      req: { method?: string; url?: string; ip?: string; query?: unknown; body?: unknown; params?: unknown; headers?: Record<string, unknown> },
      reply: { code(status: number): { send(body: unknown): unknown } },
      done: (err?: unknown) => void,
    ) => void,
  ): void;
}

/** Fastify plugin. Does not import the scanner. */
export function shieldGuard(options: GuardOptions = {}) {
  const inspect = createInspector(options);
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
      next();
    });
    done();
  };
}
