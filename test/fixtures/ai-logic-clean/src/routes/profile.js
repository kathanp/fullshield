export function register(app, User) {
  app.put('/users/:id', (req, res) => {
    if (req.user.id !== req.params.id) {
      res.status(403).end();
      return;
    }
    User.update({ name: req.body.name });
    res.json({ ok: true });
  });
}
