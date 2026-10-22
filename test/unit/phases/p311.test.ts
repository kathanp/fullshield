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
});
