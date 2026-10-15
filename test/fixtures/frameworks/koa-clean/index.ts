import Router from '@koa/router';

const router = new Router();

async function requireAuth(ctx, next) {
  if (!ctx.headers.authorization) {
    ctx.status = 401;
    return;
  }
  await next();
}

router.get('/items', requireAuth, async (ctx) => {
  const q = String(ctx.query.q ?? '');
  ctx.body = await db.query('SELECT * FROM items WHERE name = $1', [q]);
});

router.post('/items', requireAuth, async (ctx) => {
  const q = String(ctx.request.body.q);
  ctx.body = await db.query('SELECT * FROM items WHERE name = $1', [q]);
});

export default router;
