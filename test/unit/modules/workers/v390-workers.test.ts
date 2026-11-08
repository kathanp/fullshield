import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runScan } from '../../../../src/core/engine.js';
import { WORKERS_FLAG, scanWorkersSources } from '../../../../src/modules/workers/index.js';

const saved = process.env[WORKERS_FLAG];

afterEach(() => {
  if (saved === undefined) {delete process.env[WORKERS_FLAG];}
  else {process.env[WORKERS_FLAG] = saved;}
});

async function findings(source: string) {
  return scanWorkersSources([{ file: 'app.js', source }]);
}

describe('3.9.0 workers module', () => {
  it('flags a BullMQ job payload that reaches SQL and stays quiet for a checked field', async () => {
    const positive = await findings(`
      const { Worker } = require('bullmq');
      new Worker('mail', async (job) => { db.query(job.data.sql); });
    `);
    const negative = await findings(`
      const { Worker } = require('bullmq');
      new Worker('mail', async (job) => {
        const id = Number(job.data.id);
        db.query('SELECT * FROM t WHERE id = ' + id);
      });
    `);
    expect(positive.map((item) => item.ruleId)).toContain('WORKERS-SQL-001');
    expect(positive.map((item) => item.message)).toContain('BullMQ job payload reaches a SQL call.');
    expect(negative).toEqual([]);
  });

  it('flags a bee-queue job payload that reaches a shell and stays quiet for a constant', async () => {
    const positive = await findings(`
      const Queue = require('bee-queue');
      const queue = new Queue('mail');
      queue.process(async (job) => { exec(job.data.cmd); });
    `);
    const negative = await findings(`
      const Queue = require('bee-queue');
      const queue = new Queue('mail');
      queue.process(async (job) => { exec('echo ok'); });
    `);
    expect(positive.map((item) => item.ruleId)).toContain('WORKERS-CMD-001');
    expect(positive.map((item) => item.message)).toContain('bee-queue job payload reaches a shell call.');
    expect(negative).toEqual([]);
  });

  it('flags an SQS record body that reaches a path and stays quiet when an allowlist rejects it', async () => {
    const positive = await findings(`
      exports.handler = async (event) => {
        for (const record of event.Records) {
          fs.readFileSync(record.body);
        }
      };
    `);
    const negative = await findings(`
      exports.handler = async (event) => {
        for (const record of event.Records) {
          if (!allow.includes(record.body)) return;
          fs.readFileSync(record.body);
        }
      };
    `);
    expect(positive.map((item) => item.ruleId)).toContain('WORKERS-PATH-001');
    expect(positive.map((item) => item.message)).toContain('SQS record body reaches a path call.');
    expect(negative).toEqual([]);
  });

  it('flags a socket message that reaches a URL and stays quiet for a constant URL', async () => {
    const positive = await findings(`
      socket.on('message', (msg) => { fetch(msg); });
    `);
    const negative = await findings(`
      socket.on('message', (msg) => { fetch('https://example.com'); });
    `);
    expect(positive.map((item) => item.ruleId)).toContain('WORKERS-SSRF-001');
    expect(positive.map((item) => item.message)).toContain('WebSocket or Socket.IO message reaches a URL call.');
    expect(negative).toEqual([]);
  });

  it('does not treat a file that only contains bull and exec as this module', async () => {
    const found = await findings(`
      const bull = 'bull';
      exec('ls');
    `);
    expect(found).toEqual([]);
  });

  it('stays off the default scan and stays quiet on clean-app with the flag on', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fs-workers-app-'));
    await writeFile(join(dir, 'app.js'), `const { Worker } = require('bullmq');\nnew Worker('mail', async (job) => { db.query(job.data.sql); });\n`, 'utf8');
    await writeFile(join(dir, 'package.json'), '{"name":"a","version":"1.0.0"}\n', 'utf8');
    delete process.env[WORKERS_FLAG];
    const off = await runScan({ cwd: dir, offline: true });
    expect(off.metadata.modulesRequested).toEqual(['deps', 'secrets', 'sast', 'config']);
    expect(off.findings.some((item) => item.ruleId.startsWith('WORKERS-'))).toBe(false);
    process.env[WORKERS_FLAG] = '1';
    const clean = await runScan({
      cwd: join(import.meta.dirname, '../../../fixtures/clean-app'),
      modules: ['workers'],
      offline: true,
    });
    expect(clean.findings).toEqual([]);
  });
});
