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
});
