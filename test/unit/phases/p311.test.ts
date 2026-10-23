import { afterEach, describe, expect, it } from 'vitest';

import { annotateRoutes, enabled, FLAG, type RouteDraft } from '../../../src/phases/p311.js';

function route(reaches: RouteDraft['reaches'], routeOrder = 10): RouteDraft {
  return { method: 'GET', path: '/a', file: 'app.js', line: 1, routeOrder, reaches };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 311 authentication mechanism', () => {
  it('returns the same routes when the flag is off', () => {
    const routes = [route([{ id: 'main', steps: [{ name: 'session', order: 1, shape: 'middleware' }] }])];
    expect(enabled()).toBe(false);
    expect(annotateRoutes(routes)).toBe(routes);
  });

  it('stores catalog mechanisms that dominate the handler', () => {
    process.env[FLAG] = '1';
    const cases: { name: string; extra?: Record<string, unknown>; kind: string }[] = [
      { name: 'passport.authenticate', extra: { strategy: 'local', options: { session: false } }, kind: 'passport:local' },
      { name: 'express-jwt', extra: { options: { algorithms: ['HS256'] } }, kind: 'jwt' },
      { name: 'express-session', kind: 'session' },
      { name: 'apiKey', extra: { options: { apiKeyFrom: 'header' } }, kind: 'apikey' },
      { name: 'getServerSession', kind: 'framework:next-auth' },
      { name: 'UseGuards', kind: 'framework:nest' },
      { name: 'fastify-auth', kind: 'framework:fastify' },
    ];
    for (const item of cases) {
      const out = annotateRoutes([
        route([{ id: 'main', steps: [{ name: item.name, order: 1, shape: 'middleware', ...item.extra }] }]),
      ]);
      const first = out[0];
      expect(first && 'auth' in first ? first.auth.kind : '').toBe(item.kind);
    }
  });

  it('leaves none when middleware is registered after the route', () => {
    process.env[FLAG] = '1';
    const out = annotateRoutes([route([{ id: 'late', steps: [{ name: 'session', order: 20, shape: 'middleware' }] }])]);
    const first = out[0];
    expect(first && 'auth' in first ? first.auth.kind : '').toBe('none');
  });

  it('stores an unlisted authenticate function as unknown and not as session', () => {
    process.env[FLAG] = '1';
    const out = annotateRoutes([route([{ id: 'u', steps: [{ name: 'authenticate', order: 1, shape: 'middleware' }] }])]);
    const first = out[0];
    const kind = first && 'auth' in first ? first.auth.kind : '';
    expect(kind).toBe('unknown');
    expect(kind).not.toBe('session');
  });

  it('does not treat a login form render as a mechanism', () => {
    process.env[FLAG] = '1';
    const out = annotateRoutes([route([{ id: 'form', steps: [{ name: 'login', order: 1, shape: 'render-form' }] }])]);
    const first = out[0];
    expect(first && 'auth' in first ? first.auth.kind : '').toBe('none');
  });

  it('combines none, unknown, and disagreeing mechanisms', () => {
    process.env[FLAG] = '1';
    const empty = annotateRoutes([route([])]);
    expect(empty[0] && 'auth' in empty[0] ? empty[0].auth : undefined).toMatchObject({ kind: 'none', uniform: true, witnessPaths: [], authenticated: false });
    const mixed = annotateRoutes([route([
      { id: 'open', steps: [] },
      { id: 'auth', steps: [{ name: 'jwt', order: 1, shape: 'middleware' }] },
    ])]);
    expect(mixed[0] && 'auth' in mixed[0] ? mixed[0].auth : undefined).toMatchObject({ kind: 'none', uniform: false, witnessPaths: ['open'], authenticated: false });
    const logger = annotateRoutes([route([
      { id: 'a', steps: [] },
      { id: 'b', steps: [{ name: 'logger', order: 1, shape: 'middleware' }] },
    ])]);
    expect(logger[0] && 'auth' in logger[0] ? logger[0].auth : undefined).toMatchObject({ kind: 'none', uniform: true, witnessPaths: [] });
    const unknown = annotateRoutes([route([{ id: 'u', steps: [{ name: 'guard', order: 1, shape: 'middleware', options: { session: true } }] }])]);
    expect(unknown[0] && 'auth' in unknown[0] ? unknown[0].auth : undefined).toMatchObject({ kind: 'unknown', uniform: true, options: { session: true } });
    const both = annotateRoutes([route([
      { id: 'jwt', steps: [{ name: 'jsonwebtoken', order: 1, shape: 'middleware' }] },
      { id: 'session', steps: [{ name: 'cookie-session', order: 1, shape: 'middleware' }] },
    ])]);
    expect(both[0] && 'auth' in both[0] ? both[0].auth : undefined).toMatchObject({ kind: 'jwt', uniform: false, witnessPaths: ['session'], authenticated: false });
    const skipped = annotateRoutes([route([
      { id: 'form', steps: [{ name: 'login', order: 1, shape: 'render-form' }, { name: 'session', order: 10, shape: 'middleware' }] },
    ])]);
    expect(skipped[0] && 'auth' in skipped[0] ? skipped[0].auth.kind : '').toBe('none');
    const custom = annotateRoutes([
      route([{ id: 'custom', steps: [{ name: 'myAuth', order: 1, shape: 'middleware' }] }]),
    ], { frameworkNames: ['myAuth'] });
    expect(custom[0] && 'auth' in custom[0] ? custom[0].auth.kind : '').toBe('framework:custom:myAuth');
    const aliases = ['passport', 'apikey', 'NextAuth', 'next-auth', 'NestGuard', 'fastifyAuth'] as const;
    for (const name of aliases) {
      const out = annotateRoutes([route([{ id: name, steps: [{ name, order: 1, shape: 'middleware', strategy: name === 'passport' ? undefined : 'google' }] }])]);
      expect(out[0] && 'auth' in out[0] ? out[0].auth.kind : '').not.toBe('none');
    }
    const local = annotateRoutes([route([{ id: 'p', steps: [{ name: 'passport.authenticate', order: 1, shape: 'middleware' }] }])]);
    expect(local[0] && 'auth' in local[0] ? local[0].auth.kind : '').toBe('passport:local');
  });
});
