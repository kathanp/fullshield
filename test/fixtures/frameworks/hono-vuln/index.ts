import { Hono } from 'hono';

const app = new Hono();

app.get('/items', async (c) => {
  const q = c.req.query('q');
  return c.json(User.find({ q }));
});

app.post('/items', async (c) => {
  const body = await c.req.json();
  db.query('SELECT * FROM items WHERE name = ' + body.q);
  return c.json(body);
});

app.get('/items/:id', async (c) => {
  const id = c.req.param('id');
  db.query('SELECT * FROM items WHERE id = ' + id);
  return c.json({ id });
});

export default app;
