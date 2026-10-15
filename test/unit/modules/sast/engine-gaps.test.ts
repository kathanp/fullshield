import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { runConfigAstChecks } from '../../../../src/modules/config/astChecks.js';
import { runSastOnText } from '../../../../src/modules/sast/engine.js';

async function has(code: string, ruleId: string): Promise<boolean> {
  return (await runSastOnText('fixture.js', code)).some((f) => f.ruleId === ruleId);
}

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function scanFiles(files: Record<string, string>) {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-eng-'));
  dirs.push(dir);
  for (const [rel, src] of Object.entries(files)) {
    const dest = join(dir, rel);
    await mkdir(join(dest, '..'), { recursive: true });
    await writeFile(dest, src);
  }
  return scan({ cwd: dir, modules: ['sast'] });
}

describe('phase 26c — engine gaps (generic fixtures)', () => {
  describe('propagation: method-call return inherits receiver taint', () => {
    it('flags exec of a substring taken from a tainted string via match()[]', async () => {
      await expect(
        has(
          `const { exec } = require('child_process');\napp.post('/x', (req, res) => {\n  const item = req.body.content;\n  const url = item.match(/url=(.*)/)[1];\n  exec('id ' + url);\n});`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag match()[] of a literal then exec', async () => {
      await expect(
        has(
          `const { exec } = require('child_process');\napp.post('/x', (req, res) => {\n  const url = 'https://example.com/a'.match(/url=(.*)/)[1];\n  exec('id ' + url);\n});`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('propagation: helper parameter is tainted at the sink', () => {
    it('flags res.redirect when the target is a parameter seeded from req.query', async () => {
      await expect(
        has(
          `function sendAway(target, res) {\n  return res.redirect(target);\n}\napp.get('/r', (req, res) => {\n  sendAway(req.query.next, res);\n});`,
          'SAST-REDIRECT-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag a helper redirect to a literal', async () => {
      await expect(
        has(
          `function sendAway(target, res) {\n  return res.redirect(target);\n}\napp.get('/r', (req, res) => {\n  sendAway('/home', res);\n});`,
          'SAST-REDIRECT-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('propagation: return value across files', () => {
    it('flags exec of a value returned from another file that reads req.query', async () => {
      const result = await scanFiles({
        'pull.js': `function pull(req) {\n  return req.query.cmd;\n}\nmodule.exports.pull = pull;\n`,
        'run.js': `const { exec } = require('child_process');\nconst { pull } = require('./pull');\nmodule.exports = function (req, res) {\n  exec('sh ' + pull(req));\n};\n`,
      });
      expect(result.findings.some((f) => f.ruleId === 'SAST-CMDI-001' && f.file === 'run.js')).toBe(true);
    });

    it('does not flag exec of a value returned as a literal from another file', async () => {
      const result = await scanFiles({
        'pull.js': `function pull(req) {\n  return 'status';\n}\nmodule.exports.pull = pull;\n`,
        'run.js': `const { exec } = require('child_process');\nconst { pull } = require('./pull');\nmodule.exports = function (req, res) {\n  exec('sh ' + pull(req));\n};\n`,
      });
      expect(result.findings.filter((f) => f.ruleId === 'SAST-CMDI-001')).toEqual([]);
    });
  });

  describe('sink matching: archive extract on a tainted receiver', () => {
    it('flags extractAllTo when the archive object was built from an upload', async () => {
      await expect(
        has(
          `const AdmZip = require('adm-zip');\napp.post('/i', (req, res) => {\n  const zip = AdmZip(req.files.import.data);\n  zip.extractAllTo('/tmp/out', true);\n});`,
          'SAST-PATH-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag extractAllTo of a static archive path', async () => {
      await expect(
        has(
          `const AdmZip = require('adm-zip');\napp.post('/i', (req, res) => {\n  const zip = AdmZip('backup.zip');\n  zip.extractAllTo('/tmp/out', true);\n});`,
          'SAST-PATH-001',
        ),
      ).resolves.toBe(false);
    });
  });
});

describe('phase 26c — config finding line is the express() call', () => {
  it('attributes missing helmet to the express() line', async () => {
    const src = `const express = require('express');\nconst app = express();\n`;
    const findings = await runConfigAstChecks('server.js', src);
    const helmet = findings.filter((f) => f.ruleId === 'CONFIG-HELMET-001');
    expect(helmet.some((f) => f.line === 2)).toBe(true);
  });
});
