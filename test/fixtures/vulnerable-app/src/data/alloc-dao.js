'use strict';
const db = require('../db');

function byThreshold(threshold) {
  return db.query('SELECT * FROM alloc WHERE value > ' + threshold);
}

module.exports = { byThreshold };
