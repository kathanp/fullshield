import { describe, expect, it } from 'vitest';

import { runSastOnText } from '../../../../src/modules/sast/engine.js';

async function has(code: string, ruleId: string): Promise<boolean> {
  return (await runSastOnText('fixture.js', code)).some((f) => f.ruleId === ruleId);
}

describe('SAST-SQLI-001', () => {
  it('flags tainted input concatenated into a query string', async () => {
    await expect(
      has(
        `app.get('/u', (req, res) => { db.query('SELECT * FROM t WHERE id = ' + req.query.id); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
    await expect(
      has(
        `app.get('/u', (req, res) => { const id = req.query.id; db.query(\`SELECT * FROM t WHERE id = \${id}\`); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
  });

  it('does not flag a parameterized query', async () => {
    await expect(
      has(
        `app.get('/u', (req, res) => { db.query('SELECT * FROM t WHERE id = $1', [req.query.id]); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(false);
  });
});

describe('SAST-CMDI-001', () => {
  it('flags tainted input reaching exec / spawn with shell:true', async () => {
    await expect(
      has(
        `const { exec } = require('child_process');\napp.post('/r', (req, res) => { exec('ping ' + req.body.host); });`,
        'SAST-CMDI-001',
      ),
    ).resolves.toBe(true);
    await expect(
      has(
        `const { spawn } = require('child_process');\napp.post('/r', (req, res) => { spawn('sh', ['-c', req.body.cmd], { shell: true }); });`,
        'SAST-CMDI-001',
      ),
    ).resolves.toBe(true);
  });

  it('does not flag execFile with an argument array and no shell', async () => {
    await expect(
      has(
        `const { execFile } = require('child_process');\napp.post('/r', (req, res) => { execFile('ping', ['-c', '1', req.body.host]); });`,
        'SAST-CMDI-001',
      ),
    ).resolves.toBe(false);
  });
});

describe('SAST-PATH-001', () => {
  it('flags tainted input passed to sendFile / fs without a prefix check', async () => {
    await expect(
      has(`app.get('/f', (req, res) => { res.sendFile(req.query.name); });`, 'SAST-PATH-001'),
    ).resolves.toBe(true);
    await expect(
      has(
        `const fs = require('fs');\napp.get('/f', (req, res) => { fs.readFile(req.query.name, cb); });`,
        'SAST-PATH-001',
      ),
    ).resolves.toBe(true);
  });

  it('does not flag path.resolve plus startsWith prefix check', async () => {
    await expect(
      has(
        `const path = require('path');\nconst BASE = '/var/data';\napp.get('/f', (req, res) => {\n  const resolved = path.resolve(BASE, req.query.name);\n  if (!resolved.startsWith(BASE)) return res.status(400).end();\n  res.sendFile(resolved);\n});`,
        'SAST-PATH-001',
      ),
    ).resolves.toBe(false);
  });
});

describe('SAST-EVAL-001', () => {
  it('flags eval / new Function / vm.runInNewContext with a non-literal', async () => {
    await expect(has(`app.get('/c', (req, res) => { eval(req.query.expr); });`, 'SAST-EVAL-001')).resolves.toBe(
      true,
    );
    await expect(has(`const f = new Function(userInput);`, 'SAST-EVAL-001')).resolves.toBe(true);
    await expect(has(`const vm = require('vm');\nvm.runInNewContext(code);`, 'SAST-EVAL-001')).resolves.toBe(
      true,
    );
  });

  it('does not flag eval of a string literal', async () => {
    await expect(has(`eval('1 + 1');`, 'SAST-EVAL-001')).resolves.toBe(false);
  });

  it('flags library eval of a non-literal (mathjs.eval pattern)', async () => {
    await expect(
      has(
        `const mathjs = { eval };\napp.post('/e', (req, res) => { mathjs.eval(req.body.eqn); });`,
        'SAST-EVAL-001',
      ),
    ).resolves.toBe(true);
    await expect(has(`mathjs.eval('1 + 2');`, 'SAST-EVAL-001')).resolves.toBe(false);
  });
});

describe('SAST-JWT-001', () => {
  it('flags jwt.decode used for auth and verify with algorithms none / missing', async () => {
    await expect(
      has(`const jwt = require('jsonwebtoken');\nconst p = jwt.decode(token);`, 'SAST-JWT-001'),
    ).resolves.toBe(true);
    await expect(
      has(
        `const jwt = require('jsonwebtoken');\njwt.verify(token, secret, { algorithms: ['none'] });`,
        'SAST-JWT-001',
      ),
    ).resolves.toBe(true);
    await expect(
      has(`const jwt = require('jsonwebtoken');\njwt.verify(token, secret);`, 'SAST-JWT-001'),
    ).resolves.toBe(true);
  });

  it('does not flag jwt.verify with an explicit safe algorithm list', async () => {
    await expect(
      has(
        `const jwt = require('jsonwebtoken');\njwt.verify(token, secret, { algorithms: ['HS256'] });`,
        'SAST-JWT-001',
      ),
    ).resolves.toBe(false);
  });
});

describe('SAST-CRYPTO-001', () => {
  it('flags Math.random used for a token and md5 near a password', async () => {
    await expect(has(`const sessionToken = Math.random().toString(36);`, 'SAST-CRYPTO-001')).resolves.toBe(
      true,
    );
    await expect(
      has(
        `const crypto = require('crypto');\nfunction hashPassword(password) { return crypto.createHash('md5').update(password).digest('hex'); }`,
        'SAST-CRYPTO-001',
      ),
    ).resolves.toBe(true);
  });

  it('does not flag crypto.randomUUID or sha256 unrelated to passwords', async () => {
    await expect(
      has(`const sessionToken = require('crypto').randomUUID();`, 'SAST-CRYPTO-001'),
    ).resolves.toBe(false);
    await expect(
      has(
        `const crypto = require('crypto');\nconst h = crypto.createHash('sha256').update(data).digest('hex');`,
        'SAST-CRYPTO-001',
      ),
    ).resolves.toBe(false);
  });
});
