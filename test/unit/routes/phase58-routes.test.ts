import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { renderRouteTable, routeMap } from '../../../src/routes/index.js';

const app = join(import.meta.dirname, '../../fixtures/routes-app');

describe('phase 58 route map', () => {
  it('prints an authenticated route and an unauthenticated sink route and does not scan clean-app', async () => {
    const rows = await routeMap(app, ['src/index.js']);
    const text = renderRouteTable(rows);
    expect(text).toContain('POST\t/login\trequireAuth');
    expect(text).toContain('sql');
    expect(text).toContain('PUT\t/note\t-');
    expect(text).toContain('path');
    expect(text).not.toMatch(/idor|ownership/i);
    const clean = await scan({
      cwd: join(import.meta.dirname, '../../fixtures/clean-app'),
      modules: ['sast'],
      offline: true,
    });
    expect(clean.findings.filter((finding) => finding.module === 'sast')).toEqual([]);
  });
});
