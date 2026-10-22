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
});
