import { describe, expect, it } from 'vitest';

import { runSastOnText } from '../../../../src/modules/sast/engine.js';

async function has(code: string, ruleId: string): Promise<boolean> {
  return (await runSastOnText('fixture.js', code)).some((f) => f.ruleId === ruleId);
}

describe('sink-specific sanitizers (harden-3)', () => {
  it('still flags SQL concatenation through JSON.parse and generic parse', async () => {
    await expect(
      has(
        `app.get('/u', (req, res) => { db.query('SELECT * FROM t WHERE id = ' + JSON.parse(req.body).id); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
    await expect(
      has(
        `app.get('/u', (req, res) => { const id = parse(req.query.id); db.query('SELECT * FROM t WHERE id = ' + id); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
  });

  it('clears taint for SQL only when a zod/joi/yup validated result reaches the sink', async () => {
    await expect(
      has(
        `app.get('/u', (req, res) => { const id = z.string().parse(req.query.id); db.query('SELECT * FROM t WHERE id = ' + id); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(false);
    await expect(
      has(
        `app.get('/u', (req, res) => { schema.parse(req.query.id); db.query('SELECT * FROM t WHERE id = ' + req.query.id); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
  });

  it('lets encodeURIComponent clear only URL/redirect sinks, not SQL', async () => {
    await expect(
      has(
        `app.get('/g', (req, res) => { res.redirect(encodeURIComponent(req.query.next)); });`,
        'SAST-REDIRECT-001',
      ),
    ).resolves.toBe(false);
    await expect(
      has(`app.get('/p', (req, res) => { fetch(encodeURIComponent(req.query.url)); });`, 'SAST-SSRF-001'),
    ).resolves.toBe(false);
    await expect(
      has(
        `app.get('/u', (req, res) => { db.query('SELECT * FROM t WHERE id = ' + encodeURIComponent(req.query.id)); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
  });

  it('lets HTML escaping clear only XSS, not SQL', async () => {
    await expect(
      has(
        `app.get('/h', (req, res) => { res.send('<h1>' + escape(req.query.name) + '</h1>'); });`,
        'SAST-XSS-001',
      ),
    ).resolves.toBe(false);
    await expect(
      has(
        `app.get('/h', (req, res) => { res.send('<h1>' + sanitize(req.query.name) + '</h1>'); });`,
        'SAST-XSS-001',
      ),
    ).resolves.toBe(false);
    await expect(
      has(
        `app.get('/u', (req, res) => { db.query('SELECT * FROM t WHERE id = ' + escape(req.query.id)); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
  });

  it('does not treat a parameterized query as tainted SQL', async () => {
    await expect(
      has(
        `app.get('/u', (req, res) => { db.query('SELECT * FROM t WHERE id = $1', [JSON.parse(req.body).id]); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(false);
  });
});
