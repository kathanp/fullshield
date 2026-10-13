import { describe, expect, it } from 'vitest';

import { runSastOnText } from '../../../../src/modules/sast/engine.js';

async function has(code: string, ruleId: string): Promise<boolean> {
  return (await runSastOnText('fixture.js', code)).some((f) => f.ruleId === ruleId);
}

async function hasTemplate(code: string, ruleId: string): Promise<boolean> {
  return (await runSastOnText('hello.ejs', code)).some((f) => f.ruleId === ruleId);
}

describe('SAST-NOSQLI-001', () => {
  it('flags a request object passed as a Mongo filter', async () => {
    await expect(
      has(`app.post('/s', (req, res) => { User.find(req.body); });`, 'SAST-NOSQLI-001'),
    ).resolves.toBe(true);
  });

  it('does not flag a constructed filter object', async () => {
    await expect(
      has(`app.post('/s', (req, res) => { User.find({ q: req.body.q }); });`, 'SAST-NOSQLI-001'),
    ).resolves.toBe(false);
  });
});

describe('SAST-SSRF-001', () => {
  it('flags fetch of a tainted URL', async () => {
    await expect(
      has(`app.get('/p', (req, res) => { fetch(req.query.url); });`, 'SAST-SSRF-001'),
    ).resolves.toBe(true);
  });

  it('does not flag fetch of a fixed URL', async () => {
    await expect(
      has(`app.get('/p', (req, res) => { fetch('https://example.com/health'); });`, 'SAST-SSRF-001'),
    ).resolves.toBe(false);
  });

  it('flags needle.get of a tainted URL (NodeGoat research pattern)', async () => {
    await expect(
      has(
        `app.get('/r', (req, res) => { const url = req.query.url + req.query.symbol; needle.get(url); });`,
        'SAST-SSRF-001',
      ),
    ).resolves.toBe(true);
    await expect(
      has(`app.get('/r', (req, res) => { needle.get('https://example.com'); });`, 'SAST-SSRF-001'),
    ).resolves.toBe(false);
  });
});

describe('SAST-REDIRECT-001', () => {
  it('flags res.redirect of a tainted value', async () => {
    await expect(
      has(`app.get('/g', (req, res) => { res.redirect(req.query.next); });`, 'SAST-REDIRECT-001'),
    ).resolves.toBe(true);
  });

  it('does not flag redirect to a literal', async () => {
    await expect(
      has(`app.get('/g', (req, res) => { res.redirect('/home'); });`, 'SAST-REDIRECT-001'),
    ).resolves.toBe(false);
  });
});

describe('SAST-PROTO-001', () => {
  it('flags an unguarded merge of a tainted object', async () => {
    await expect(
      has(`function merge(a,b){ for (const k of Object.keys(b)) a[k]=b[k]; }\nmerge({}, req.body);`, 'SAST-PROTO-001'),
    ).resolves.toBe(true);
  });

  it('does not flag a merge that guards __proto__', async () => {
    await expect(
      has(
        `function merge(a,b){ for (const k of Object.keys(b)) { if (k === '__proto__') continue; a[k]=b[k]; } }\nmerge({}, req.body);`,
        'SAST-PROTO-001',
      ),
    ).resolves.toBe(false);
  });
});

describe('SAST-XSS-001', () => {
  it('flags tainted HTML sent to the client', async () => {
    await expect(
      has(`app.get('/h', (req, res) => { res.send('<h1>' + req.query.name + '</h1>'); });`, 'SAST-XSS-001'),
    ).resolves.toBe(true);
  });

  it('does not flag res.json of a stringified field', async () => {
    await expect(
      has(`app.get('/h', (req, res) => { res.json({ name: String(req.query.name) }); });`, 'SAST-XSS-001'),
    ).resolves.toBe(false);
  });

  it('flags unescaped EJS output and ignores include / escaped tags', async () => {
    await expect(hasTemplate('<%- name %>', 'SAST-XSS-001')).resolves.toBe(true);
    await expect(hasTemplate('<%= name %>\n<%- include(\'partial\') %>', 'SAST-XSS-001')).resolves.toBe(
      false,
    );
  });
});

describe('SAST-AUTH-001', () => {
  it('flags a data-touching route with no auth middleware', async () => {
    await expect(
      has(`app.get('/user', (req, res) => { db.query('SELECT 1'); });`, 'SAST-AUTH-001'),
    ).resolves.toBe(true);
  });

  it('does not flag a route that uses requireAuth', async () => {
    await expect(
      has(`app.get('/user', requireAuth, (req, res) => { db.query('SELECT 1'); });`, 'SAST-AUTH-001'),
    ).resolves.toBe(false);
  });
});
