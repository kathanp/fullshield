'use strict';
// Phase 75 order: router.use(requireAuth) covers only routes registered after it.
const db = { query(sql) { return sql; } };
const router = {};
const app = { use() {} };

router.get('/open', function open(req, res) {
  db.query('SELECT id FROM t WHERE n = ' + req.query.n);
  res.end('open');
});
router.use(requireAuth);
router.get('/early', function early(req, res) {
  db.query('SELECT * FROM users WHERE id = ' + req.query.id);
  res.end('early');
});
app.use('/secure', router);
