'use strict';
// Fake db client so the fixture is parseable/self-contained. Never executed.
module.exports = {
  query(sql, params, cb) {
    if (cb) cb(null, []);
  },
  find(filter, cb) {
    if (cb) cb(null, []);
  },
};
