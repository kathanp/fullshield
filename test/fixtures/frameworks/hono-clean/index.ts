import { Hono } from 'hono';

const app = new Hono();

function requireAuth(c, next) {
  if (!c.req.header('authorization')) return c.json({ error: 'unauthorized' }, 401);
  return next();
}

app.get('/items', requireAuth, async (c) => {
  const q = String(c.req.query('q') ?? '');
  const rows = await db.query('SELECT * FROM items WHERE name = $1', [q]);
  return c.json(rows);
});

app.post('/items', requireAuth, async (c) => {
  const body = await c.req.json();
  const q = String(body.q);
  const rows = await db.query('SELECT * FROM items WHERE name = $1', [q]);
  return c.json(rows);
});

export default app;
