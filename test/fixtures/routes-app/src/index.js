'use strict';
const express = require('express');
const app = express();
app.get('/health', function ok(req, res) {
  res.end('ok');
});
app.post('/login', requireAuth, function login(req, res) {
  db.query('select 1');
});
app.put('/note', function note(req, res) {
  fs.readFile(req.query.p);
});
