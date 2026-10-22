import { afterEach, describe, expect, it } from 'vitest';

import { analyzeKoaHono, enabled, FLAG } from '../../../src/phases/p309.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 309 koa and hono', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeKoaHono('app.use(async (ctx) => { db.query(ctx.query.q); });').findings).toEqual([]);
  });

  it('requires await next and a number validator', () => {
    process.env[FLAG] = '1';
    const covered = analyzeKoaHono('app.use(async (ctx, next) => { await next(); });\napp.use(async (ctx) => { db.query(ctx.query.q); });');
    expect(covered.findings[0]).toMatchObject({ framework: 'koa', finding: true });
    expect(covered.covers[0]).toMatchObject({ covers: true, dominates: false });
    const stopped = analyzeKoaHono('app.use(async (ctx, next) => { ctx.state.user = true; });\napp.use(async (ctx) => { db.query(ctx.query.q); });');
    expect(stopped.covers[0]?.covers).toBe(false);
    const late = analyzeKoaHono('app.use(async (ctx, next) => { await next(); ctx.state.user = true; });\napp.use(async (ctx) => { db.query(ctx.query.q); });');
    expect(late.covers[0]).toMatchObject({ covers: true, dominates: false });
    const early = analyzeKoaHono('app.use(async (ctx, next) => { ctx.state.user = true; await next(); });\napp.use(async (ctx) => { db.query(ctx.query.q); });');
    expect(early.covers[0]?.dominates).toBe(true);
    const hono = analyzeKoaHono("app.get('/x', (c) => { db.query(c.req.query('q')); });");
    expect(hono.findings[0]?.framework).toBe('hono');
    const cleared = analyzeKoaHono("app.get('/x', zValidator('query', z.object({ id: z.number() })), (c) => { db.query(c.req.query('id')); });");
    expect(cleared.findings).toEqual([]);
    const open = analyzeKoaHono("app.get('/x', (c) => { db.query(c.req.query('id')); });");
    expect(open.findings).toHaveLength(1);
  });
});
