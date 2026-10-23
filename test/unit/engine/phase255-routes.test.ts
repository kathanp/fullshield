import { afterEach, describe, expect, it } from 'vitest';

import { ROUTE_FLAG, buildRoutes, routesEnabled } from '../../../src/engine/routes.js';

afterEach(() => {
  delete process.env[ROUTE_FLAG];
});

const files = [
  {
    file: 'a.js',
    source: [
      "import { inner } from './b.js';",
      'const app = express();',
      "app.use('/a', requireAuth, inner);",
    ].join('\n'),
  },
  {
    file: 'b.js',
    source: [
      "import { leaf } from './c.js';",
      'export const inner = express.Router();',
      "inner.use('/b', leaf);",
    ].join('\n'),
  },
  {
    file: 'c.js',
    source: [
      'export const leaf = express.Router();',
      "leaf.get('/c', handler);",
    ].join('\n'),
  },
];

describe('phase 255 routes', () => {
  it('is off unless the flag is set', () => {
    expect(routesEnabled()).toBe(false);
    expect(buildRoutes(files)).toEqual([]);
  });

  it('joins three nested routers and inherits auth', () => {
    process.env[ROUTE_FLAG] = '1';
    const routes = buildRoutes(files);
    expect(routes).toHaveLength(1);
    expect(routes[0]).toMatchObject({
      method: 'GET',
      fullPath: '/a/b/c',
      file: 'c.js',
      handlerFn: 'handler',
      authState: 'present',
      framework: 'express',
    });
    expect(routes[0]?.middlewareChain).toContain('requireAuth');
  });

  it('does not invent auth for a router with no auth middleware', () => {
    process.env[ROUTE_FLAG] = '1';
    const open = [{
      file: 'app.js',
      source: "const app = express();\napp.get('/health', health);\n",
    }];
    const routes = buildRoutes(open);
    expect(routes[0]?.fullPath).toBe('/health');
    expect(routes[0]?.authState).not.toBe('present');
  });

  it('records routers, absent auth, and paths that are not string literals', () => {
    process.env[ROUTE_FLAG] = '1';
    const routes = buildRoutes([
      {
        file: 'app.js',
        source: [
          "import express from 'express';",
          "import kind from './missing.js';",
          'const router = express.Router();',
          'const skipped = other.notRouter();',
          'let bare;',
          'const { destructured } = express();',
          'export const published = 1;',
          "router.use('/a/', logger, child);",
          "router.get(pathName, ...mws);",
          "router.post('health', validate, handler);",
          'router.listen(3000);',
          'app.use();',
        ].join('\n'),
      },
      {
        file: 'child.js',
        source: "export const child = express.Router();\nchild.delete('leaf', handler);\n",
      },
    ]);
    expect(routes.some((route) => route.authState === 'absent')).toBe(true);
    expect(routes.some((route) => route.method === 'POST')).toBe(true);
    delete process.env[ROUTE_FLAG];
  });
});
