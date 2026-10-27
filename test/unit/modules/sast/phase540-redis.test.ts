import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';
import { redisFindings, redisOnFiles } from '../../../../src/modules/sast/redis.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_REDIS';
const ioredis = "const Redis = require('ioredis');\n";

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 540 Redis command injection', () => {
  it('registers scan --experimental-redis', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-redis');
  });

  it('fires when eval, call, or sendCommand gets request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', `${ioredis}function go(req) { client.eval(req.query.lua); }\n`);
    const redis = hits.filter((finding) => finding.ruleId === 'SAST-REDIS-001');
    expect(redis).toHaveLength(1);
    expect(redis[0]?.severity).toBe('high');
    expect(redis[0]?.cwe).toBe('CWE-94');
    expect(await ids(`${ioredis}function go(req) { client.call(req.body.cmd); }\n`)).toContain('SAST-REDIS-001');
    expect(await ids(`${ioredis}function go(req) { client.sendCommand(req.params.cmd); }\n`)).toContain('SAST-REDIS-001');
    expect(await ids(`${ioredis}function go(req) { client.evalSha(req.headers.sha); }\n`)).toContain('SAST-REDIS-001');
  });

  it('stays silent for get/set, a literal script, and a missing import', async () => {
    process.env[FLAG] = '1';
    expect(await ids(`${ioredis}function go(req) { client.get(req.query.key); }\n`)).not.toContain('SAST-REDIS-001');
    expect(await ids(`${ioredis}function go(req) { client.set(req.query.key, 'v'); }\n`)).not.toContain('SAST-REDIS-001');
    expect(await ids(`${ioredis}function go(req) { client.eval('return 1'); }\n`)).not.toContain('SAST-REDIS-001');
    expect(await ids('function go(req) { client.eval(req.query.lua); }\n')).not.toContain('SAST-REDIS-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids(`${ioredis}function go(req) { client.eval(req.query.lua); }\n`)).not.toContain('SAST-REDIS-001');
    process.env[FLAG] = '1';
    expect(await redisFindings('fixture.js', `${ioredis}function go(req) { {{{`)).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-redis-'));
    expect(await redisOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = `${ioredis}function go(req) { client.eval(req.query.lua); }\n`;
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
