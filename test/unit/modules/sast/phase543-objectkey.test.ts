import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';
import { objectkeyFindings, objectkeyOnFiles } from '../../../../src/modules/sast/objectkey.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_OBJECTKEY';
const s3 = "const { GetObjectCommand } = require('@aws-sdk/client-s3');\n";

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 543 object-storage key from request data', () => {
  it('registers scan --experimental-objectkey', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-objectkey');
  });

  it('fires when Key or Prefix is request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', `${s3}function go(req) { new GetObjectCommand({ Key: req.query.key }); }\n`);
    const objectkey = hits.filter((finding) => finding.ruleId === 'SAST-OBJECTKEY-001');
    expect(objectkey).toHaveLength(1);
    expect(objectkey[0]?.severity).toBe('high');
    expect(objectkey[0]?.cwe).toBe('CWE-22');
    expect(await ids(`${s3}function go(req) { s3.getObject({ Key: req.body.key }); }\n`)).toContain('SAST-OBJECTKEY-001');
    expect(await ids(`${s3}function go(req) { s3.listObjectsV2({ Prefix: req.params.p }); }\n`)).toContain('SAST-OBJECTKEY-001');
  });

  it('stays silent for a literal key, Bucket alone, and a missing import', async () => {
    process.env[FLAG] = '1';
    expect(await ids(`${s3}function go(req) { new GetObjectCommand({ Key: 'a' }); }\n`)).not.toContain('SAST-OBJECTKEY-001');
    expect(await ids(`${s3}function go(req) { new GetObjectCommand({ Key: 'a', Bucket: req.query.b }); }\n`)).not.toContain('SAST-OBJECTKEY-001');
    expect(await ids('function go(req) { new GetObjectCommand({ Key: req.query.key }); }\n')).not.toContain('SAST-OBJECTKEY-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids(`${s3}function go(req) { new GetObjectCommand({ Key: req.query.key }); }\n`)).not.toContain('SAST-OBJECTKEY-001');
    process.env[FLAG] = '1';
    expect(await objectkeyFindings('fixture.js', `${s3}function go(req) { {{{`)).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-objectkey-'));
    expect(await objectkeyOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = `${s3}function go(req) { new GetObjectCommand({ Key: req.query.key }); }\n`;
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
