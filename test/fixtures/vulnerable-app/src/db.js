'use strict';
// Fake db client so the fixture is parseable/self-contained. Never executed.
module.exports = {
  query(sql, paramsOrCb, maybeCb) {
    const cb = typeof paramsOrCb === 'function' ? paramsOrCb : maybeCb;
    if (cb) cb(null, []);
  },
};
