'use strict';
// Safe mirror of the vulnerable-app fixture: same features, written securely.
// Must produce ZERO high/critical findings in every phase.
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');
const { execFile } = require('child_process');
const db = require('./db');

const app = express();
app.use(helmet());
app.use(express.json({ limit: '100kb' }));

// Parameterized query: must NOT be flagged as SQL injection.
app.get('/user', (req, res) => {
  db.query('SELECT * FROM users WHERE id = $1', [req.query.id], (err, rows) => {
    res.json(rows);
  });
});

// Path resolved against a fixed base dir with a prefix check.
const FILES_DIR = path.resolve(__dirname, 'public');
app.get('/file', (req, res) => {
  const resolved = path.resolve(FILES_DIR, String(req.query.name));
  if (!resolved.startsWith(FILES_DIR + path.sep)) {
    return res.status(400).send('invalid path');
  }
  res.sendFile(resolved);
});

// execFile with an argument array and strict input validation; no shell.
app.post('/run', (req, res) => {
  const host = String(req.body.host);
  if (!/^[a-z0-9.-]{1,253}$/i.test(host)) {
    return res.status(400).send('invalid host');
  }
  execFile('ping', ['-c', '1', host], (err, out) => {
    res.send(out);
  });
});

// Cryptographically secure token; secrets come from the environment.
const sessionToken = crypto.randomUUID();
const awsKey = process.env.AWS_ACCESS_KEY_ID;

app.listen(3000);

module.exports = { app, sessionToken, awsKey };
