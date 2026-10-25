import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');

async function ids(code: string): Promise<string[]> {
  const findings = await runSastOnText('fixture.js', code);
  return findings.map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
});

describe('phase 502 field and closure taint', () => {
  it('fires through one field and one nested function, and stays silent one step further', async () => {
    const field = 'function go(req) {\n  const obj = {};\n  obj.a = req.body.id;\n  db.query(obj.a);\n  db.query(obj.b);\n}\n';
    const closure = 'function go(req) {\n  const id = req.body.id;\n  function inner() { db.query(id); }\n  inner();\n}\n';
    const deep = 'function go(req) {\n  const id = req.body.id;\n  function mid() {\n    function inner() { db.query(id); }\n  }\n}\n';
    const chain = 'function go(req) {\n  const obj = {};\n  obj.a = {};\n  obj.a.b = req.body.id;\n  db.query(obj.a.b);\n}\n';
    delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
    expect(await ids(field)).toContain('SAST-SQLI-001');
    expect(await ids(closure)).toContain('SAST-SQLI-001');
    process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 = '1';
    const fieldHits = await runSastOnText('fixture.js', field);
    expect(fieldHits.filter((finding) => finding.ruleId === 'SAST-SQLI-001')).toHaveLength(1);
    expect(fieldHits.some((finding) => finding.snippet?.includes('obj.b'))).toBe(false);
    expect(await ids(closure)).toContain('SAST-SQLI-001');
    expect(await ids(deep)).not.toContain('SAST-SQLI-001');
    expect(await ids(chain)).not.toContain('SAST-SQLI-001');
  });

  it('does not cross a shadowing declaration', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 = '1';
    const shadowName = 'function go(req) {\n  const id = req.body.id;\n  function inner() {\n    const id = "safe";\n    db.query(id);\n  }\n}\n';
    const shadowObject = 'function go(req) {\n  const obj = {};\n  obj.a = req.body.id;\n  function inner() {\n    const obj = {};\n    db.query(obj.a);\n  }\n}\n';
    const shadowFn = 'function go(req) {\n  const id = req.body.id;\n  function inner() {\n    function id() { return "x"; }\n    db.query(id());\n  }\n}\n';
    expect(await ids(shadowName)).not.toContain('SAST-SQLI-001');
    expect(await ids(shadowObject)).not.toContain('SAST-SQLI-001');
    expect(await ids(shadowFn)).not.toContain('SAST-SQLI-001');
  });

  it('does not let JSON.parse clear a stored field', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 = '1';
    const code = 'function go(req) {\n  const obj = {};\n  obj.a = JSON.parse(req.body.id);\n  db.query(obj.a);\n}\n';
    expect(await ids(code)).toContain('SAST-SQLI-001');
    const bare = 'function go(req) {\n  const obj = {};\n  obj.a = parse(req.body.id);\n  db.query(obj.a);\n}\n';
    expect(await ids(bare)).toContain('SAST-SQLI-001');
  });

  it('reaches command, path, fetch, redirect, NoSQL, and HTML send through one field', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 = '1';
    expect(await ids('function go(req) {\n  const obj = {};\n  obj.a = req.body.id;\n  exec(obj.a);\n}\n')).toContain('SAST-CMDI-001');
    expect(await ids('function go(req) {\n  const obj = {};\n  obj.a = req.query.file;\n  fs.readFile(obj.a);\n}\n')).toContain('SAST-PATH-001');
    expect(await ids('function go(req) {\n  const obj = {};\n  obj.a = req.query.url;\n  fetch(obj.a);\n}\n')).toContain('SAST-SSRF-001');
    expect(await ids('function go(req) {\n  const obj = {};\n  obj.a = req.query.to;\n  res.redirect(obj.a);\n}\n')).toContain('SAST-REDIRECT-001');
    expect(
      await ids('const mongodb = require("mongodb");\nfunction go(req) {\n  const obj = {};\n  obj.a = req.body.id;\n  ordersCollection.find({ $where: obj.a });\n}\n'),
    ).toContain('SAST-NOSQLI-001');
    expect(await ids('function go(req) {\n  const obj = {};\n  obj.a = req.body.name;\n  res.send("<p>" + obj.a + "</p>");\n}\n')).toContain('SAST-XSS-001');
  });

  it('does not flag Handlebars braces, res.json, or a url.includes helper', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 = '1';
    const hbs = await runSastOnText('view.hbs', '<p>{{ name }}</p>\n');
    expect(hbs.some((finding) => finding.ruleId === 'SAST-XSS-001')).toBe(false);
    expect(await ids('function go(req, res) {\n  res.json({ data: req.params.id });\n}\n')).not.toContain('SAST-XSS-001');
    expect(
      await ids('function isRedirectAllowed(url) {\n  let allowed = false;\n  for (const allowedUrl of redirectAllowlist) {\n    allowed = allowed || url.includes(allowedUrl);\n  }\n  return allowed;\n}\n'),
    ).not.toContain('SAST-REDIRECT-001');
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 = '1';
    const code = 'function go(req) {\n  const id = req.body.id;\n  function inner() { db.query(id); }\n}\n';
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
