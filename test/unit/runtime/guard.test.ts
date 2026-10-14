import { describe, expect, it, vi } from 'vitest';

import { shieldGuard as expressGuard } from '../../../src/runtime/express.js';
import { shieldGuard as fastifyGuard } from '../../../src/runtime/fastify.js';
import { createInspector } from '../../../src/runtime/inspect.js';

describe('runtime payload blocking', () => {
  it('blocks SQLi, XSS, and path-traversal payloads in block mode', () => {
    const inspect = createInspector({ mode: 'block' });
    expect(inspect({ path: '/q', query: { q: "' OR 1=1--" } }).event?.ruleId).toBe('RUNTIME-SQLI-001');
    expect(inspect({ path: '/q', query: { q: "' OR 1=1--" } }).block).toBe(true);
    expect(inspect({ path: '/q', query: { q: '<script>alert(1)</script>' } }).event?.ruleId).toBe(
      'RUNTIME-XSS-001',
    );
    expect(inspect({ path: '/q', query: { q: '../../etc/passwd' } }).event?.ruleId).toBe('RUNTIME-PATH-001');
    expect(inspect({ path: '/q', query: { q: 'hello' } }).block).toBe(false);
  });

  it('does not block in monitor mode but still emits onEvent', () => {
    const onEvent = vi.fn();
    const inspect = createInspector({ mode: 'monitor', onEvent });
    const result = inspect({ path: '/q', query: { q: 'UNION SELECT password FROM users' } });
    expect(result.block).toBe(false);
    expect(onEvent).toHaveBeenCalled();
  });

  it('rate-limits auth routes in block mode', () => {
    const inspect = createInspector({
      mode: 'block',
      authRoutes: ['/login'],
      rateLimit: { windowMs: 60_000, max: 2 },
    });
    expect(inspect({ path: '/login', ip: '1.1.1.1' }).block).toBe(false);
    expect(inspect({ path: '/login', ip: '1.1.1.1' }).block).toBe(false);
    expect(inspect({ path: '/login', ip: '1.1.1.1' }).event?.ruleId).toBe('RUNTIME-RATELIMIT-001');
  });

  it('flags a 401 spike and a new param after the anomaly learning window', () => {
    let now = 0;
    const events: string[] = [];
    const inspect = createInspector({
      anomaly: {
        learnMinutes: 1,
        now: () => now,
        onAnomaly: (e) => events.push(e.sample),
      },
    });
    for (let i = 0; i < 10; i += 1) {
      inspect({ path: '/login', query: { user: 'a' }, statusCode: 200 });
    }
    now = 61_000;
    const spike = inspect({ path: '/login', query: { user: 'a' }, statusCode: 401 });
    expect(spike.event?.ruleId).toBe('RUNTIME-ANOMALY-001');
    expect(events).toContain('401-spike');
    const probe = inspect({ path: '/login', query: { user: 'a', admin: '1' }, statusCode: 200 });
    expect(probe.event?.sample).toBe('new-param');
  });

  it('does not log the raw request body on events', () => {
    const onEvent = vi.fn();
    const inspect = createInspector({ mode: 'block', onEvent });
    inspect({ path: '/q', body: { password: "' OR 1=1--" } });
    const event = onEvent.mock.calls[0]?.[0] as { sample: string };
    expect(JSON.stringify(event)).not.toContain('password');
  });
});

describe('framework adapters', () => {
  it('Express middleware returns 403 in block mode', () => {
    const mw = expressGuard({ mode: 'block' });
    let status = 0;
    let body: unknown;
    mw(
      { path: '/q', query: { q: "' OR 1=1--" } },
      { status: (code: number) => ({ json: (b: unknown) => { status = code; body = b; } }) },
      () => {
        throw new Error('next should not be called');
      },
    );
    expect(status).toBe(403);
    expect(body).toMatchObject({ error: 'blocked' });
  });

  it('Fastify plugin hooks preHandler and calls next when clean', () => {
    const plugin = fastifyGuard({ mode: 'block' });
    let hooked = false;
    let nextCalled = false;
    plugin(
      {
        addHook(_name, hook) {
          hooked = true;
          hook({ url: '/ok', query: { q: 'ok' }, body: {}, params: {}, headers: {} }, { code: () => ({ send: () => undefined }) }, () => {
            nextCalled = true;
          });
        },
      },
      {},
      () => undefined,
    );
    expect(hooked).toBe(true);
    expect(nextCalled).toBe(true);
  });
});
