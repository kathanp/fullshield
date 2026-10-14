import { contextFromRequest, enterRaspContext, type IncomingLike } from './context.js';
import { emitRaspEvent, raspMode, runDecide } from './enable.js';
import { RASP_FAIL_OPEN, RaspBlockedError } from './types.js';

interface ExpressLikeRes {
  status?(code: number): { json(body: unknown): unknown };
  statusCode?: number;
  end?(body?: unknown): unknown;
}

export function raspContext() {
  return function raspContextMiddleware(
    req: IncomingLike,
    res: ExpressLikeRes,
    next: (err?: unknown) => void,
  ): void {
    const ctx = contextFromRequest(req);
    try {
      const proto = runDecide('proto', null, ctx);
      if (proto.block && proto.ruleId) {
        emitRaspEvent({
          ruleId: proto.ruleId,
          path: ctx.path,
          ip: ctx.ip,
          sample: 'prototype-key',
        });
        if (raspMode() === 'block') {
          if (typeof res.status === 'function') {
            res.status(403).json({ error: 'blocked', ruleId: proto.ruleId });
            return;
          }
          res.statusCode = 403;
          res.end?.(JSON.stringify({ error: 'blocked', ruleId: proto.ruleId }));
          return;
        }
      }
    } catch (err) {
      if (err instanceof RaspBlockedError) {
        if (typeof res.status === 'function') {
          res.status(403).json({ error: 'blocked', ruleId: err.ruleId });
          return;
        }
        throw err;
      }
      emitRaspEvent({
        ruleId: RASP_FAIL_OPEN,
        path: ctx.path,
        ip: ctx.ip,
        sample: 'hook-error',
      });
    }
    enterRaspContext(ctx, () => {
      next();
    });
  };
}
