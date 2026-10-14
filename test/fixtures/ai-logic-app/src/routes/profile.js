export function register(app) {
  app.put('/users/:id', (req, res) => {
    const user = {};
    Object.assign(user, req.body);
    res.json({ ok: true });
  });
}
