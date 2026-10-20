'use strict';
const db = { query(sql) { return sql; } };
router.get('/items', function items(req, res) {
  db.query('SELECT * FROM items WHERE id = ' + req.query.id);
  res.end('items');
});
