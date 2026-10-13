'use strict';
// Safe mirror of the vulnerable-app fixture: same features, written securely.
// Must produce ZERO high/critical findings in every phase.
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const { execFile } = require('child_process');
const db = require('./db');

const app = express();
app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.use(cors({ origin: ['https://example.com'], credentials: true }));

function requireAuth(req, res, next) {
  if (!req.headers.authorization) return res.status(401).end();
  next();
}

// Parameterized query: must NOT be flagged as SQL injection.
app.get('/user', requireAuth, (req, res) => {
  db.query('SELECT * FROM users WHERE id = $1', [req.query.id], (err, rows) => {
    res.json(rows);
  });
});

// Path resolved against a fixed base dir with a prefix check.
const FILES_DIR = path.resolve(__dirname, 'public');
app.get('/file', requireAuth, (req, res) => {
  const resolved = path.resolve(FILES_DIR, String(req.query.name));
  if (!resolved.startsWith(FILES_DIR + path.sep)) {
    return res.status(400).send('invalid path');
  }
  res.sendFile(resolved);
});

// execFile with an argument array and strict input validation; no shell.
app.post('/run', requireAuth, (req, res) => {
  const host = String(req.body.host);
  if (!/^[a-z0-9.-]{1,253}$/i.test(host)) {
    return res.status(400).send('invalid host');
  }
  execFile('ping', ['-c', '1', host], (err, out) => {
    res.send(out);
  });
});

// jwt.verify with an explicit algorithm allow-list (must NOT flag SAST-JWT-001).
const jwt = require('jsonwebtoken');
app.get('/profile', requireAuth, (req, res) => {
  const payload = jwt.verify(String(req.headers.authorization), process.env.JWT_SECRET, {
    algorithms: ['HS256'],
  });
  res.json(payload);
});

app.post('/search', requireAuth, (req, res) => {
  db.find({ q: String(req.body.q) }, (err, rows) => {
    res.json(rows);
  });
});

app.get('/proxy', requireAuth, (req, res) => {
  fetch('https://example.com/health').then((r) => r.text()).then((t) => res.send(t));
});

app.get('/go', requireAuth, (req, res) => {
  const next = req.query.next === '/home' ? '/home' : '/';
  res.redirect(next);
});

function merge(a, b) {
  for (const k of Object.keys(b)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (b[k] && typeof b[k] === 'object') merge(a[k] || {}, b[k]);
    else a[k] = b[k];
  }
  return a;
}
app.post('/settings', requireAuth, (req, res) => {
  res.json(merge({}, req.body));
});

app.get('/hello', requireAuth, (req, res) => {
  res.json({ name: String(req.query.name) });
});

const loginLimiter = rateLimit({ windowMs: 60_000, max: 5 });
app.post('/login', loginLimiter, (req, res) => {
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  res.status(500).json({ error: 'internal error' });
});

// Cryptographically secure token; secrets come from the environment.
const sessionToken = crypto.randomUUID();
const awsKey = process.env.AWS_ACCESS_KEY_ID;

// Docs-style URI with angle-bracket placeholders — must not flag SECRET-DBURL-001.
const DOCS_URI = 'mongodb://<username>:<password>@cluster.example.com/db';

// Literal library eval and a fixed URL — must not flag EVAL / SSRF.
const mathjs = { eval: (s) => s };
mathjs.eval('1 + 2');
const needle = { get: (url) => fetch(url) };
needle.get('https://example.com/health');

app.listen(3000);

module.exports = { app, sessionToken, awsKey };
