'use strict';
// Cross-file taint (Phase 13): route → service → dao (3 files).
const { getAlloc } = require('../services/alloc');

function handleAlloc(req, res) {
  res.json(getAlloc(req.query.threshold));
}

module.exports = { handleAlloc };
