import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';
import { workerFindings, workerOnFiles } from '../../../../src/modules/sast/worker.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_WORKER';
const threads = "const { Worker } = require('worker_threads');\n";

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 544 worker entry from request data', () => {
  it('registers scan --experimental-worker', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-worker');
  });

  it('fires when the worker path or workerData is request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', `${threads}function go(req) { new Worker(req.query.path); }\n`);
    const worker = hits.filter((finding) => finding.ruleId === 'SAST-WORKER-001');
    expect(worker).toHaveLength(1);
    expect(worker[0]?.severity).toBe('high');
    expect(worker[0]?.cwe).toBe('CWE-94');
    expect(await ids(`${threads}function go(req) { new Worker('./w.js', { workerData: req.body }); }\n`)).toContain('SAST-WORKER-001');
    expect(await ids("const { Worker } = require('node:worker_threads');\nfunction go(req) { new Worker(req.params.path); }\n")).toContain('SAST-WORKER-001');
  });

  it('stays silent for a literal path and a missing import', async () => {
    process.env[FLAG] = '1';
    expect(await ids(`${threads}function go(req) { new Worker('./w.js'); }\n`)).not.toContain('SAST-WORKER-001');
    expect(await ids(`${threads}function go(req) { new Worker('./w.js', { workerData: { id: 1 } }); }\n`)).not.toContain('SAST-WORKER-001');
    expect(await ids('function go(req) { new Worker(req.query.path); }\n')).not.toContain('SAST-WORKER-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids(`${threads}function go(req) { new Worker(req.query.path); }\n`)).not.toContain('SAST-WORKER-001');
    process.env[FLAG] = '1';
    expect(await workerFindings('fixture.js', `${threads}function go(req) { {{{`)).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-worker-'));
    expect(await workerOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = `${threads}function go(req) { new Worker(req.query.path); }\n`;
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
