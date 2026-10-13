'use strict';
// Router-only file: importing express for Router() must not flag CONFIG-HELMET-001.
const express = require('express');
const router = express.Router();

router.get('/health', (req, res) => {
  res.json({ ok: true });
});

module.exports = { router };
