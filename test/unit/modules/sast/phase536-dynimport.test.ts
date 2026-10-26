import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { dynimportFindings, dynimportOnFiles } from '../../../../src/modules/sast/dynimport.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_DYNIMPORT';

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 536 dynamic import of request data', () => {
  it('registers scan --experimental-dynimport', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-dynimport');
  });

  it('fires when import() is called with request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', 'async function go(req) { await import(req.query.mod); }\n');
    const dyn = hits.filter((finding) => finding.ruleId === 'SAST-DYNIMPORT-001');
    expect(dyn).toHaveLength(1);
    expect(dyn[0]?.severity).toBe('high');
    expect(dyn[0]?.cwe).toBe('CWE-829');
    expect(dyn[0]?.line).toBe(1);
    expect(await ids('async function go(req) { const mod = req.body.mod; await import(mod); }\n')).toContain('SAST-DYNIMPORT-001');
    expect(await ids('async function go(req) { await import(req.params.mod); }\n')).toContain('SAST-DYNIMPORT-001');
    expect(await ids('async function go(req) { await import(req.headers.mod); }\n')).toContain('SAST-DYNIMPORT-001');
  });

  it('stays silent for a literal specifier and for a binding that is not request data', async () => {
    process.env[FLAG] = '1';
    expect(await ids("async function go(req) { await import('./local.js'); }\n")).not.toContain('SAST-DYNIMPORT-001');
    expect(await ids("async function go(req) { const name = 'local.js'; await import(name); }\n")).not.toContain('SAST-DYNIMPORT-001');
    expect(await ids('async function go(req) { await import(other); }\n')).not.toContain('SAST-DYNIMPORT-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids('async function go(req) { await import(req.query.mod); }\n')).not.toContain('SAST-DYNIMPORT-001');
    process.env[FLAG] = '1';
    expect(await dynimportFindings('fixture.js', 'async function go(req) { {{{')).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-dynimport-'));
    expect(await dynimportOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = 'async function go(req) { await import(req.query.mod); }\n';
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
