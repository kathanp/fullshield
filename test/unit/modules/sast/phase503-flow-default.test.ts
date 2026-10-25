import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const field = 'function go(req) {\n  const obj = {};\n  obj.a = req.body.id;\n  db.query(obj.a);\n}\n';

afterEach(() => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
});

describe('phase 503 field and closure taint on the default scan', () => {
  it('fires when the flag is unset and when it is 0', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
    const unset = await runSastOnText('fixture.js', field);
    expect(unset.some((finding) => finding.ruleId === 'SAST-SQLI-001')).toBe(true);
    process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 = '0';
    const zero = await runSastOnText('fixture.js', field);
    expect(zero.some((finding) => finding.ruleId === 'SAST-SQLI-001')).toBe(true);
  });

  it('does not carry process.argv into a nested function', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
    const code = [
      "const fs = require('fs');",
      "const path = require('path');",
      'async function main() {',
      '  const dir = process.argv[2];',
      '  fs.mkdir(dir);',
      '  await Promise.all([1].map(async () => {',
      "    fs.mkdir(path.join(dir, 'pkg'));",
      '  }));',
      '}',
      '',
    ].join('\n');
    const findings = await runSastOnText('fixture.js', code);
    const hits = findings.filter((finding) => finding.ruleId === 'SAST-PATH-001');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.line).toBe(5);
  });

  it('does not treat a field as tainted before it is assigned', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
    const code = [
      'function handle(req, res) {',
      '  const clean = req.url;',
      '  res.redirect(clean);',
      "  req.url = req.headers['x-matched-path'];",
      '}',
      '',
    ].join('\n');
    const findings = await runSastOnText('fixture.js', code);
    expect(findings.some((finding) => finding.ruleId === 'SAST-REDIRECT-001')).toBe(false);
  });

  it('still carries request data through one nested function', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
    const code = [
      "const fs = require('fs');",
      'function handle(req) {',
      '  const name = req.query.file;',
      '  [1].map(function () { fs.readFile(name); });',
      '}',
      '',
    ].join('\n');
    const findings = await runSastOnText('fixture.js', code);
    expect(findings.some((finding) => finding.ruleId === 'SAST-PATH-001')).toBe(true);
  });

  it('keeps clean-app at zero findings with the flag unset', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });
});
