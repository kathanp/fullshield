export function register(app, db) {
  app.get('/users/:id', (req, res) => {
    const row = db.users.findById(req.params.id);
    res.json(row);
  });
}
