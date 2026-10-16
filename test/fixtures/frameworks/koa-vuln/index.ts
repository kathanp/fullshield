import Router from '@koa/router';

const router = new Router();

router.get('/items', async (ctx) => {
  ctx.body = User.find({ q: ctx.query.q });
});

router.post('/items', async (ctx) => {
  db.query('SELECT * FROM items WHERE name = ' + ctx.request.body.q);
  ctx.body = ctx.request.body;
});

router.get('/items/:id', async (ctx) => {
  db.query('SELECT * FROM items WHERE id = ' + ctx.params.id);
  ctx.body = { id: ctx.params.id };
});

export default router;
