import { createServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  formatSummary,
  loadLastScan,
  notifyEmail,
  notifySlack,
  notifyWebhook,
} from '../../../src/notifiers/index.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fullshield-notify-'));
  await mkdir(join(dir, '.fullshield'), { recursive: true });
  await writeFile(
    join(dir, '.fullshield/last-scan.json'),
    JSON.stringify({
      summary: { total: 2, bySeverity: { high: 2, critical: 0, medium: 0, low: 0, info: 0 } },
      metadata: { version: '0.1.0', cwd: dir },
    }),
  );
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('notifiers', () => {
  it('loads the last scan summary and formats it', async () => {
    const summary = await loadLastScan(dir);
    expect(summary.total).toBe(2);
    expect(formatSummary(summary)).toContain('2 finding');
    expect(formatSummary(summary)).toContain('2 high');
  });

  it('POSTs Slack and generic webhook JSON to a local mock server', async () => {
    const received: unknown[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        received.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        res.statusCode = 200;
        res.end('ok');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    const url = `http://127.0.0.1:${port}/hook`;
    const summary = await loadLastScan(dir);
    await notifySlack(url, summary);
    await notifyWebhook(url, summary);
    server.close();
    expect(received).toHaveLength(2);
    expect(JSON.stringify(received)).toContain('2 finding');
  });

  it('sends an SMTP DATA payload to a local mock server', async () => {
    let data = '';
    const server = createNetServer((sock) => {
      sock.write('220 test\r\n');
      sock.on('data', (chunk: Buffer) => {
        data += chunk.toString('utf8');
        sock.end();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    await notifyEmail({
      host: '127.0.0.1',
      port,
      from: 'scan@example.com',
      to: 'dev@example.com',
      summary: await loadLastScan(dir),
    });
    server.close();
    expect(data).toContain('MAIL FROM:<scan@example.com>');
    expect(data).toContain('2 finding');
  });
});
