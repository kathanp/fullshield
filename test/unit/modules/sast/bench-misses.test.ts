import { describe, expect, it } from 'vitest';

import { runSastOnText } from '../../../../src/modules/sast/engine.js';

async function has(code: string, ruleId: string, filename = 'fixture.js'): Promise<boolean> {
  return (await runSastOnText(filename, code)).some((f) => f.ruleId === ruleId);
}

describe('phase 26b — in-scope bench misses (stable)', () => {
  describe('Juice Shop NoSQL $where (trackOrder / showProductReviews)', () => {
    it('flags a tainted $where string on find (no experimental flag)', async () => {
      delete process.env.FULLSHIELD_EXPERIMENTAL_SAST_GAPS;
      await expect(
        has(
          `app.get('/track/:id', (req, res) => {\n  const id = String(req.params.id);\n  db.ordersCollection.find({ $where: \`this.orderId === '\${id}'\` });\n});`,
          'SAST-NOSQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/reviews/:id', (req, res) => {\n  const id = req.params.id;\n  db.reviewsCollection.find({ $where: 'this.product == ' + id });\n});`,
          'SAST-NOSQLI-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag find with a field equality object', async () => {
      await expect(
        has(
          `app.get('/reviews/:id', (req, res) => { db.reviewsCollection.find({ product: String(req.params.id) }); });`,
          'SAST-NOSQLI-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('Juice Shop open redirect via destructured query.to', () => {
    it('flags res.redirect of query.to from a destructured Request', async () => {
      await expect(
        has(
          `export function performRedirect() {\n  return ({ query }, res) => {\n    const toUrl = query.to;\n    if (isRedirectAllowed(toUrl)) res.redirect(toUrl);\n  };\n}`,
          'SAST-REDIRECT-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag redirect to a literal', async () => {
      await expect(
        has(
          `export function performRedirect() {\n  return ({ query }, res) => { res.redirect('/home'); };\n}`,
          'SAST-REDIRECT-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('DVNA md5 reset token', () => {
    it('flags the md5 npm helper used as a reset token', async () => {
      await expect(
        has(
          `var md5 = require('md5');\nmodule.exports.resetPw = function (req, res) {\n  if (req.query.token == md5(req.query.login)) { res.render('resetpw'); }\n};`,
          'SAST-CRYPTO-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag sha256 of a login', async () => {
      await expect(
        has(
          `const crypto = require('crypto');\nmodule.exports.resetPw = function (req, res) {\n  const token = crypto.createHash('sha256').update(req.query.login).digest('hex');\n};`,
          'SAST-CRYPTO-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('NodeGoat Swig autoescape: false', () => {
    it('flags swig.setDefaults({ autoescape: false })', async () => {
      await expect(
        has(
          `const swig = require('swig');\nswig.setDefaults({ autoescape: false });`,
          'SAST-XSS-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag autoescape: true', async () => {
      await expect(
        has(
          `const swig = require('swig');\nswig.setDefaults({ autoescape: true });`,
          'SAST-XSS-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('known limitations (not claimed)', () => {
    it('flags Mongo { _id: req.body.id } unless the value is coerced', async () => {
      await expect(
        has(
          `app.post('/reviews', (req, res) => {\n  db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true });\n});`,
          'SAST-NOSQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.post('/reviews', (req, res) => {\n  db.reviewsCollection.update({ _id: String(req.body.id) }, { $set: { message: String(req.body.message) } }, { multi: true });\n});`,
          'SAST-NOSQLI-001',
        ),
      ).resolves.toBe(false);
    });

    it('does not flag url.includes(allowedUrl) allowlist helpers', async () => {
      await expect(
        has(
          `export const isRedirectAllowed = (url) => {\n  let allowed = false;\n  for (const allowedUrl of redirectAllowlist) {\n    allowed = allowed || url.includes(allowedUrl);\n  }\n  return allowed;\n};`,
          'SAST-REDIRECT-001',
        ),
      ).resolves.toBe(false);
    });

    it('does not flag res.json of a tainted id as HTML XSS', async () => {
      await expect(
        has(
          `app.get('/track/:id', (req, res) => {\n  const id = req.params.id;\n  res.json({ data: [{ orderId: id }] });\n});`,
          'SAST-XSS-001',
        ),
      ).resolves.toBe(false);
    });
  });
});
