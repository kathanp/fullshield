export default function handler(req, res) {
  db.query('SELECT * FROM t WHERE id = ' + req.query.id);
  res.json({ ok: true });
}
