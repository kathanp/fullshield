import { afterEach, describe, expect, it } from 'vitest';

import { analyzeTrpc, enabled, FLAG } from '../../../src/phases/p297.js';

const SOURCE = `
const appRouter = router({
  pub: t.procedure.input(z.string()).query(({ input }) => { db.query(input); }),
  prot: t.procedure.use(auth).input(z.number()).query(({ input }) => { db.query(input); }),
});
const post = router({
  byId: protectedProcedure.input(z.string()).query(({ input }) => { db.query(input); }),
});
mergeRouters(post);
const odd = t.procedure.input(z.custom()).query(({ input }) => { db.query(input); });
`;

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 297 trpc', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeTrpc(SOURCE).routes).toEqual([]);
  });

  it('keeps auth on the procedure that declared it and clears z.number()', () => {
    process.env[FLAG] = '1';
    const result = analyzeTrpc(SOURCE);
    const pub = result.routes.find((route) => route.path === 'pub');
    const prot = result.routes.find((route) => route.path === 'prot');
    const byId = result.routes.find((route) => route.path === 'post.byId');
    expect(pub).toMatchObject({ authState: 'absent', injection: true });
    expect(prot).toMatchObject({ authState: 'present', injection: false });
    expect(byId).toMatchObject({ authState: 'present', injection: true });
    expect(result.events.map((event) => event.reason)).toContain('custom');
  });

  it('classifies regex, enum, any, and nested routers', () => {
    process.env[FLAG] = '1';
    expect(analyzeTrpc(':::').routes).toEqual([]);
    const source = [
      'const nested = router({ child: { deep: t.procedure.mutation(({ input }) => { db.query(input + "x"); }) } });',
      'const direct = query(({ input }) => { db.query(input.name); });',
      'const rx = t.procedure.input(z.string().regex(/^\\d+$/)).query(({ input }) => { db.query(input); });',
      'const open = t.procedure.input(z.string().regex(/\\d+/)).query(({ input }) => { db.query(input); });',
      'const word = t.procedure.input(z.string().regex("^a$")).query(({ input }) => { db.query(input); });',
      'const loose = t.procedure.input(z.any()).query(({ input }) => { db.query(input); });',
      'const anyIn = t.procedure.input(z.custom()).subscription(({ input }) => { db.query(input); });',
      'const listed = t.procedure.input(z.enum(["a"])).query(({ input }) => { db.query(input); });',
      'const plain = t.procedure.input(z.string()).query(({ input }) => { db.query(input); });',
    ].join('\n');
    const result = analyzeTrpc(source);
    expect(result.routes.some((route) => route.path === 'nested.child.deep')).toBe(true);
    expect(result.routes.find((route) => route.path === 'rx')?.injection).toBe(false);
    expect(result.routes.find((route) => route.path === 'anyIn')?.injection).toBe(true);
    expect(result.events.length).toBeGreaterThan(0);
    delete process.env[FLAG];
  });
});
