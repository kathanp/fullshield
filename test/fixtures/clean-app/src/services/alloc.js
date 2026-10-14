'use strict';
const { byThreshold } = require('../data/alloc-dao');

function getAlloc(threshold) {
  return byThreshold(threshold);
}

module.exports = { getAlloc };
