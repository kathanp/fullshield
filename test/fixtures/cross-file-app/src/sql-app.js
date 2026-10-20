'use strict';
const { build, literal } = require('./sql-lib');
function handler(req) {
  db.query(build(req.query.id));
  db.query(literal());
}
