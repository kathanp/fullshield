import { afterEach, describe, expect, it } from 'vitest';

import { analyzeNextApp, enabled, FLAG } from '../../../src/phases/p294.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 294 next app router', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeNextApp({ 'app/page.tsx': 'export default function Page() { db.query(req.query.q); }' }).routes).toEqual([]);
  });

  it('builds a path without groups and still reports an unawaited promise', () => {
    process.env[FLAG] = '1';
    const result = analyzeNextApp({
      'app/(marketing)/about/page.tsx': 'export default function Page({ searchParams }) { db.query(searchParams.q); }',
      'app/items/[...slug]/route.ts': 'export function GET(request) { db.query(request.url); }',
      'app/p/page.tsx': 'export default async function Page({ params }) { db.query(params.id); }',
      'pages/old.tsx': 'export default function Page({ query }) { db.query(query.q); }',
      'app/@[id]/page.tsx': 'export default function Page() { db.query(params.id); }',
    });
    expect(result.routes.map((route) => route.fullPath)).toEqual(['/about', '/items/[...slug]', '/p']);
    expect(result.routes[0]?.fullPath.includes('marketing')).toBe(false);
    expect(result.events.map((event) => event.reason)).toEqual(expect.arrayContaining(['promise form', 'slot dynamic']));
    expect(result.findings.map((finding) => finding.file)).not.toContain('pages/old.tsx');
    expect(result.findings.map((finding) => finding.file)).toContain('app/p/page.tsx');
  });
});
