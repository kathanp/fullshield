'use strict';
router.get('/late', function late(req, res) {
  db.query('select 1');
});
router.use(requireAuth);
