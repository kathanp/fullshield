import { afterEach, describe, expect, it } from 'vitest';

import { analyzeMeta, enabled, FLAG } from '../../../src/phases/p303.js';
import { resetVersionCache } from '../../../src/phases/p310.js';

afterEach(() => {
  delete process.env[FLAG];
  delete process.env.FULLSHIELD_EXPERIMENTAL_VERKEY;
  resetVersionCache();
});

describe('phase 303 meta frameworks', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeMeta({ 'app/routes/notes.$id.tsx': 'export function loader({ params }) { db.query(params.id); }' }, { framework: 'remix', version: '2.0.0' }).routes).toEqual([]);
  });

  it('reports one route per framework and keeps locals on that request', () => {
    process.env[FLAG] = '1';
    const remix = analyzeMeta({
      'app/routes/notes.$id.tsx': 'export function loader({ request, params }) { db.query(params.id); }',
      'app/routes/locals.tsx': 'export function loader({ request, context }) { context.locals.q = request.url; }\nexport function action({ context }) { db.query(context.locals.q); }',
      'app/routes/other.tsx': 'export function loader({ context }) { db.query(context.locals.q); }',
    }, { framework: 'remix', version: '2.9.0', packagePath: 'nm/remix' });
    expect(remix.routes.find((route) => route.file.endsWith('notes.$id.tsx'))).toMatchObject({ fullPath: '/notes/:id', finding: true });
    expect(remix.routes.find((route) => route.file.endsWith('locals.tsx'))?.finding).toBe(true);
    expect(remix.routes.find((route) => route.file.endsWith('other.tsx'))?.finding).toBe(false);
    const svelte = analyzeMeta({ 'src/routes/notes/[id]/+page.server.ts': 'export function load({ params }) { db.query(params.id); }' }, { framework: 'sveltekit', version: '2.0.0', packagePath: 'nm/svelte' });
    expect(svelte.routes[0]).toMatchObject({ fullPath: '/notes/:id', finding: true });
    const nuxt = analyzeMeta({ 'server/api/notes/[id].ts': 'export default defineEventHandler((event) => { db.query(getQuery(event).q); });' }, { framework: 'nuxt', version: '3.8.0', packagePath: 'nm/nuxt' });
    expect(nuxt.routes[0]).toMatchObject({ fullPath: '/api/notes/:id', finding: true });
  });

  it('rejects a gap version and a file that matches two grammars', () => {
    process.env[FLAG] = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_VERKEY = '1';
    const gap = analyzeMeta({ 'app/routes/notes.$id.tsx': 'export function loader({ params }) { db.query(params.id); }' }, { framework: 'remix', version: '1.0.0', packagePath: 'nm/remix1' });
    expect(gap.routes).toEqual([]);
    expect(gap.events.map((event) => event.reason)).toContain('version-gap');
    const both = analyzeMeta({ 'app/routes/mix.ts': 'export function loader() {}\ndefineEventHandler(() => { db.query(getQuery(event).q); });' }, { framework: 'auto', version: '2.0.0', packagePath: 'nm/auto', rows: [{ id: 'any', appliesTo: '>=1 <9' }] });
    expect(both.routes).toEqual([]);
    expect(both.events.map((event) => event.reason)).toContain('two grammars');
  });
});
