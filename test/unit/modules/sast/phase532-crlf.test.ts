import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { crlfFindings, crlfOnFiles } from '../../../../src/modules/sast/crlf.js';
import { sastHit } from '../../../../src/modules/sast/fileScan.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';
import type { AstNode } from '../../../../src/modules/sast/types.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_CRLF';

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 532 HTTP header injection', () => {
  it('registers scan --experimental-crlf', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-crlf');
  });

  it('fires when the header value is request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', 'function go(req) { res.setHeader("X-Name", req.query.name); }\n');
    const crlf = hits.filter((finding) => finding.ruleId === 'SAST-CRLF-001');
    expect(crlf).toHaveLength(1);
    expect(crlf[0]?.severity).toBe('high');
    expect(crlf[0]?.cwe).toBe('CWE-113');
    expect(crlf[0]?.line).toBe(1);
    expect(await ids('function go(req) { res.append("X-Name", req.body.name); }\n')).toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.header("X-Name", req.params.name); }\n')).toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.set("X-Name", req.headers.name); }\n')).toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { const name = req.query.name; res.setHeader("X-Name", name); }\n')).toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.set({ "X-Name": req.query.name }); }\n')).toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.set({ XName: req.query.name }); }\n')).toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.writeHead(200, { Location: req.query.next }); }\n')).toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.writeHead(200, "OK", { "X-Name": req.params.name }); }\n')).toContain('SAST-CRLF-001');
  });

  it('stays silent for a literal value, a status, a header name, and a spread', async () => {
    process.env[FLAG] = '1';
    expect(await ids('function go(req) { res.setHeader("Content-Type", "application/json"); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.writeHead(200); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.writeHead(req.query.code); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.setHeader(req.query.name, "ok"); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.setHeader(...req.query.parts); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.set({ ...req.query, "X-Name": "ok" }); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { res.writeHead(200, ...req.query.parts); }\n')).not.toContain('SAST-CRLF-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids('function go(req) { res.setHeader("X-Name", req.query.name); }\n')).not.toContain('SAST-CRLF-001');
    process.env[FLAG] = '1';
    expect(await crlfFindings('fixture.js', 'function go(req) { {{{')).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-crlf-'));
    expect(await crlfOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
    const bare = sastHit({
      ruleId: 'SAST-CRLF-001',
      title: 'HTTP header injection',
      cwe: 'CWE-113',
      message: 'Request data is written into an HTTP header.',
      remediation: 'Set the header to a literal.',
      filename: 'fixture.js',
      source: 'res.setHeader()',
      node: { type: 'Identifier', name: 'res' } as AstNode,
    });
    expect(bare.snippet).toBe('');
    expect(bare.line).toBeUndefined();
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('does not treat cache, map, or session set as a header', async () => {
    process.env[FLAG] = '1';
    expect(await ids('function go(req) { reply.set("X-Name", req.query.name); }\n')).toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { cache.set("k", req.query.name); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { map.set("k", req.query.name); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { session.set("k", req.query.name); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { set("X-Name", req.query.name); }\n')).not.toContain('SAST-CRLF-001');
    expect(await ids('function go(req) { app.res.set("X-Name", req.query.name); }\n')).not.toContain('SAST-CRLF-001');
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = 'function go(req) { res.setHeader("X-Name", req.query.name); }\n';
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
