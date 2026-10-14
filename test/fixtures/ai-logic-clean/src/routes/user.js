export function register(app, db) {
  app.get('/users/:id', (req, res) => {
    if (req.user.id !== req.params.id) {
      res.status(403).end();
      return;
    }
    const row = db.users.findById(req.params.id);
    res.json(row);
  });
}
