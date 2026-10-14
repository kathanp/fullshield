import { createServer } from 'node:http';
import { cp, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { runInit } from '../../../src/cli/commands/init.js';
import { diffNewFindings } from '../../../src/core/watch.js';
import type { Finding } from '../../../src/core/finding.js';

const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const dirs: string[] = [];

afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

function finding(id: string, ruleId = 'DEPS-VULN-001'): Finding {
  return {
    id,
    ruleId,
    module: 'deps',
    title: 'v',
    severity: 'high',
    confidence: 'high',
    message: 'm',
    remediation: 'r',
  };
}

async function runCli(args: string[]): Promise<{ out: string; err: string; exit: number | undefined }> {
  const out: string[] = [];
  const err: string[] = [];
  const prev = process.exitCode;
  process.exitCode = undefined;
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  await program.parseAsync(['node', 'fullshield', ...args]);
  const exit = process.exitCode;
  process.exitCode = prev;
  return { out: out.join('\n'), err: err.join('\n'), exit };
}

describe('diffNewFindings', () => {
  it('returns only findings whose id was not in the previous scan', () => {
    const prev = [finding('aaaa')];
    const next = [finding('aaaa'), finding('bbbb')];
    expect(diffNewFindings(next, new Set(prev.map((f) => f.id))).map((f) => f.id)).toEqual(['bbbb']);
    expect(diffNewFindings(next, new Set(next.map((f) => f.id)))).toEqual([]);
  });
});

describe('fullshield watch', () => {
  it('alerts on the first deps scan and sends no webhook on a second unchanged run', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-watch-'));
    dirs.push(dir);
    await cp(vulnerableApp, dir, { recursive: true });

    const posted: string[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        posted.push(Buffer.concat(chunks).toString('utf8'));
        res.statusCode = 200;
        res.end('ok');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    const hook = `http://127.0.0.1:${port}/hook`;

    const first = await runCli(['watch', dir, '--offline', '--webhook', hook]);
    expect(first.out).toMatch(/new/i);
    expect(posted.length).toBe(1);

    const second = await runCli(['watch', dir, '--offline', '--webhook', hook]);
    expect(second.out).toMatch(/no new/i);
    expect(posted.length).toBe(1);
    server.close();
  });
});

describe('init daily watch workflow', () => {
  it('writes a scheduled GitHub Action that runs fullshield watch', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-watch-init-'));
    dirs.push(dir);
    const result = await runInit({ cwd: dir });
    expect(result.written).toContain('.github/workflows/fullshield-watch.yml');
    const { readFile } = await import('node:fs/promises');
    const yaml = await readFile(join(dir, '.github/workflows/fullshield-watch.yml'), 'utf8');
    expect(yaml).toContain('schedule:');
    expect(yaml).toMatch(/cron:/);
    expect(yaml).toContain('fullshield watch');
    expect(yaml).not.toMatch(/^\t/m);
  });
});
