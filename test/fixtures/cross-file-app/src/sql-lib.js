'use strict';
function build(id) {
  return "SELECT * FROM t WHERE id = '" + id + "'";
}
module.exports = { build };
function literal() {
  return 'SELECT 1';
}
module.exports.literal = literal;
