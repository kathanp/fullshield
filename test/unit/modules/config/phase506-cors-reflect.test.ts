import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runConfigAstChecks } from '../../../../src/modules/config/astChecks.js';
import { scanCorsReflect } from '../../../../src/modules/config/corsReflect.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_CORSREFLECT';
const dirs: string[] = [];

async function ids(code: string): Promise<string[]> {
  return (await scanCorsReflect('app.js', code)).map((finding) => finding.ruleId);
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('phase 506 reflected CORS origin', () => {
  it('registers scan --experimental-cors-reflect', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-cors-reflect');
  });

  it('fires when the origin is the request Origin and credentials are allowed', async () => {
    const cors = await scanCorsReflect('app.js', `function go(req, res) {\n  cors({ origin: req.headers.origin, credentials: true });\n}\n`);
    const hits = cors.filter((finding) => finding.ruleId === 'CONFIG-CORS-002');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe('high');
    expect(hits[0]?.line).toBe(2);
    expect(await ids(`function go(req, res) {\n  const origin = req.headers.origin;\n  cors({ origin, credentials: true });\n}\n`)).toContain('CONFIG-CORS-002');
    expect(
      await ids(`function go(req, res) {\n  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n  res.setHeader('Access-Control-Allow-Credentials', 'true');\n}\n`),
    ).toContain('CONFIG-CORS-002');
  });

  it('stays silent for a fixed origin and does not replace the star rule', async () => {
    expect(await ids(`function go(req, res) {\n  cors({ origin: 'https://example.com', credentials: true });\n}\n`)).not.toContain('CONFIG-CORS-002');
    expect(await ids(`function go(req, res) {\n  cors({ origin: req.headers.origin });\n}\n`)).not.toContain('CONFIG-CORS-002');
    expect(await ids(`function go(req, res) {\n  let origin;\n  origin = req.headers.origin;\n  cors({ origin, credentials: true });\n}\n`)).toContain('CONFIG-CORS-002');
    expect(
      await ids(`function go(req, res) {\n  res.set({ 'Access-Control-Allow-Origin': req.headers.origin, 'Access-Control-Allow-Credentials': 'true' });\n}\n`),
    ).toContain('CONFIG-CORS-002');
    expect(await scanCorsReflect('app.js', 'cors(')).toEqual([]);
    const star = `function go(req, res) {\n  cors({ origin: '*', credentials: true });\n}\n`;
    expect(await ids(star)).not.toContain('CONFIG-CORS-002');
    const stable = await runConfigAstChecks('app.js', star);
    expect(stable.some((finding) => finding.ruleId === 'CONFIG-CORS-001')).toBe(true);
  });

  it('stays off the default scan and on when the flag is 1', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-cors-'));
    dirs.push(cwd);
    await writeFile(join(cwd, 'app.js'), `function go(req, res) {\n  cors({ origin: req.headers.origin, credentials: true });\n}\n`);
    await writeFile(join(cwd, 'package.json'), '{"name":"cors-app","version":"1.0.0"}\n');
    delete process.env[FLAG];
    const off = await scan({ cwd, modules: ['config'], offline: true });
    expect(off.findings.some((finding) => finding.ruleId === 'CONFIG-CORS-002')).toBe(false);
    process.env[FLAG] = '1';
    const on = await scan({ cwd, modules: ['config'], offline: true });
    expect(on.findings.some((finding) => finding.ruleId === 'CONFIG-CORS-002')).toBe(true);
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    const code = `function go(req, res) {\n  cors({ origin: req.headers.origin, credentials: true });\n}\n`;
    const key = async () => JSON.stringify((await scanCorsReflect('app.js', code)).map((finding) => [finding.ruleId, finding.line, finding.severity]));
    expect(await key()).toBe(await key());
  });
});
