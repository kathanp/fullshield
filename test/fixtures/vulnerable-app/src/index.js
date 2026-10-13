'use strict';
// INTENTIONALLY VULNERABLE fixture app. Every vulnerability here is seeded on
// purpose so FullShield rules can detect it. Never run or deploy this code.
const express = require('express');
const { exec } = require('child_process');
const db = require('./db');

const app = express();
// no helmet() -> CONFIG-HELMET-001
app.use(express.json()); // no size limit -> CONFIG-BODYLIMIT-001

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

// SAST-CRYPTO-001: Math.random for a token
const sessionToken = Math.random().toString(36).slice(2);

// SECRET-AWS-001: fake AWS key (AWS docs example key), concatenated so GitHub
// push protection is not tripped. This is NOT a real credential.
const AWS_ACCESS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';

app.listen(3000);

module.exports = { app, sessionToken, AWS_ACCESS_KEY };
