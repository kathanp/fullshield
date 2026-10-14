'use strict';
const { getAlloc } = require('../services/alloc');

function handleAlloc(req, res) {
  res.json(getAlloc(req.query.threshold));
}

module.exports = { handleAlloc };
