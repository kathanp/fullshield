'use strict';
router.use(requireAuth);
router.get('/early', function early(req, res) {
  db.query('select 1');
});
