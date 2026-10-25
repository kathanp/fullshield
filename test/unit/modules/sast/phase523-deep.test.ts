import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_DEEP';

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 523 deeper checks on the existing rules', () => {
  it('registers scan --experimental-deep', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-deep');
  });

  it('stays off the default scan', async () => {
    const code = `function go(req, res) { res.end('<b>' + req.query.x + '</b>'); }\n`;
    expect(await ids(code)).not.toContain('SAST-XSS-001');
  });

  it('fires the extra matches and skips the safe variants', async () => {
    process.env[FLAG] = '1';
    expect(await ids(`function go(req, res) { res.end('<b>' + req.query.x + '</b>'); }\n`)).toContain('SAST-XSS-001');
    expect(await ids(`function go(req, res) { res.status(401).end(); }\n`)).not.toContain('SAST-XSS-001');
    expect(await ids(`const http = require('http');\nfunction go(req) { http.request({ hostname: req.query.host }); }\n`)).toContain('SAST-SSRF-001');
    expect(await ids(`const http = require('http');\nfunction go() { http.request({ hostname: 'example.com' }); }\n`)).not.toContain('SAST-SSRF-001');
    expect(await ids(`function go(req) { Bun.file(req.query.path); }\n`)).toContain('SAST-PATH-001');
    expect(await ids(`const fs = require('fs');\nfunction go(req) { fs.glob(req.query.pattern); }\n`)).toContain('SAST-PATH-001');
    expect(await ids(`function go(req) { Bun.file('notes.txt'); }\n`)).not.toContain('SAST-PATH-001');
    expect(await ids(`function go(req, res) { res.location(req.query.next); }\n`)).toContain('SAST-REDIRECT-001');
    expect(await ids(`function go(res) { res.location('/home'); }\n`)).not.toContain('SAST-REDIRECT-001');
    expect(await ids(`const jwt = require('jsonwebtoken');\nfunction go(req) { jwt.verify(req.headers.authorization, 's', { algorithms: [] }); }\n`)).toContain('SAST-JWT-001');
    expect(await ids(`const jwt = require('jsonwebtoken');\nfunction go(req) { jwt.verify(req.headers.authorization, process.env.JWT_SECRET, { algorithms: ['HS256'] }); }\n`)).not.toContain('SAST-JWT-001');
    expect(await ids(`function go(req) { Object.assign({}, req.body); }\n`)).toContain('SAST-PROTO-001');
    expect(await ids(`function go(req) { if (k === '__proto__') { return; } merge({}, req.body); }\n`)).not.toContain('SAST-PROTO-001');
    expect(await ids(`function go() { Object.assign({}, { ok: true }); }\n`)).not.toContain('SAST-PROTO-001');
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = `function go(req, res) { res.location(req.query.next); }\n`;
    const key = async () => JSON.stringify((await runSastOnText('app.js', code)).map((finding) => [finding.ruleId, finding.line]));
    expect(await key()).toBe(await key());
  });
});
