'use strict';
// INTENTIONALLY VULNERABLE fixture app. Every vulnerability here is seeded on
// purpose so FullShield rules can detect it. Never run or deploy this code.
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const db = require('./db');
require('mongodb'); // marks db.find as a Mongo receiver for SAST-NOSQLI-001
const lodash = require('lodash');
lodash.get({}, 'x');

const app = express();
// no helmet() -> CONFIG-HELMET-001
app.use(express.json()); // no size limit -> CONFIG-BODYLIMIT-001
// CONFIG-CORS-001: wildcard origin with credentials
app.use(cors({ origin: '*', credentials: true }));

// SAST-SQLI-001: tainted input concatenated into SQL
app.get('/user', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ' + req.query.id, (err, rows) => {
    res.json(rows);
  });
});

// SAST-PATH-001: tainted input used as a file path with no resolve/prefix check
app.get('/file', (req, res) => {
  res.sendFile(req.query.name);
});

// SAST-CMDI-001: tainted input reaching exec
app.post('/run', (req, res) => {
  exec(`ping ${req.body.host}`, (err, out) => {
    res.send(out);
  });
});

// SAST-EVAL-001: eval of non-literal tainted input
app.get('/calc', (req, res) => {
  res.send(String(eval(req.query.expr)));
});

// SAST-EVAL-001: library eval (DVNA mathjs.eval pattern)
const mathjs = { eval };
app.post('/eqn', (req, res) => {
  res.send(String(mathjs.eval(req.body.eqn)));
});

// SAST-CRYPTO-001: Math.random for a token
const sessionToken = Math.random().toString(36).slice(2);

// SECRET-AWS-001: fake AWS key (AWS docs example key), concatenated so GitHub
// push protection is not tripped. This is NOT a real credential.
const AWS_ACCESS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';

// SECRET-STRIPE-001 — fake, concatenated.
const STRIPE_KEY = 'sk_test_' + 'FAKEfakeFAKEfakeFAKE1234';

// SECRET-JWT-001 — hardcoded JWT signing secret (fake).
const JWT_SECRET = 'super-secret-jwt-signing-key-fixture';

// SAST-JWT-001: decode used as authentication (verify is missing).
const jwt = require('jsonwebtoken');
app.get('/profile', (req, res) => {
  const payload = jwt.decode(req.headers.authorization);
  res.json(payload);
});

// SAST-NOSQLI-001: request object passed straight into a Mongo-style filter.
app.post('/search', (req, res) => {
  db.find(req.body);
});

// SAST-SSRF-001: tainted URL passed to fetch.
app.get('/proxy', (req, res) => {
  fetch(req.query.url).then((r) => r.text()).then((t) => res.send(t));
});

// SAST-SSRF-001: HTTP client other than fetch/axios (NodeGoat needle pattern)
const needle = { get: (url) => fetch(url) };
app.get('/research', (req, res) => {
  const url = req.query.url + req.query.symbol;
  needle.get(url);
});

// SAST-REDIRECT-001: tainted open redirect.
app.get('/go', (req, res) => {
  res.redirect(req.query.next);
});

// SAST-PROTO-001: recursive merge of a tainted object with no __proto__ guard.
function merge(a, b) {
  for (const k of Object.keys(b)) {
    if (b[k] && typeof b[k] === 'object') merge(a[k] || {}, b[k]);
    else a[k] = b[k];
  }
  return a;
}
app.post('/settings', (req, res) => {
  res.json(merge({}, req.body));
});

// SAST-XSS-001: tainted input interpolated into an HTML response.
app.get('/hello', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

// CONFIG-RATELIMIT-001: login route with no rate limiter.
app.post('/login', (req, res) => {
  res.json({ ok: true, user: req.body.user });
});

// CONFIG-ERRSTACK-001: error handler leaks stack traces.
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});

app.listen(3000);

module.exports = { app, sessionToken, AWS_ACCESS_KEY, STRIPE_KEY, JWT_SECRET };
