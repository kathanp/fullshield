import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { buildCanary } from '../../../src/confirm/index.js';
import { confirmStartedApp } from '../../../src/confirm/launch.js';
import { applyRecordedEvidence } from '../../../src/evidence/record.js';
import type { Finding } from '../../../src/core/finding.js';

const dirs: string[] = [];

afterEach(async () => {
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

function finding(file: string): Finding {
  return {
    id: '1',
    ruleId: 'SAST-SQLI-001',
    module: 'sast',
    title: 'sql',
    message: 'sql',
    severity: 'high',
    confidence: 'high',
    file,
    line: 1,
    remediation: 'bind it',
  };
}

describe('3.6.1 confirm starts a local app', () => {
  it('builds an SSRF canary that stays on 127.0.0.1', () => {
    const payload = buildCanary('ssrf', 'FULLSHIELD_CANARY_abc');
    expect(payload.startsWith('http://127.0.0.1/')).toBe(true);
    expect(payload).toContain('FULLSHIELD_CANARY_abc');
  });

  it('starts the entry on 127.0.0.1, sends a canary, and stops the process', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-confirm-app-'));
    dirs.push(cwd);
    await writeFile(
      join(cwd, 'app.js'),
      `const http = require('http');
const { URL } = require('url');
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  res.end(url.searchParams.get('id') ?? '');
}).listen(Number(process.env.PORT), '127.0.0.1');
`,
      'utf8',
    );
    const result = await confirmStartedApp({
      entry: 'app.js',
      cwd,
      canaryToken: 'FULLSHIELD_CANARY_abc',
      routes: [{ kind: 'sql', method: 'GET', path: '/user', param: 'id' }],
    });
    expect(result.url.startsWith('http://127.0.0.1:')).toBe(true);
    expect(result.confirmations[0]?.status).toBe('confirmed');
    await expect(fetch(result.url)).rejects.toThrow();
  });

  it('does not keep a listener after the app fails to open the port', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'fs-confirm-down-'));
    dirs.push(cwd);
    await writeFile(join(cwd, 'app.js'), 'process.exit(0);\n', 'utf8');
    await expect(confirmStartedApp({
      entry: 'app.js',
      cwd,
      routes: [{ kind: 'sql', method: 'GET', path: '/', param: 'id' }],
      timeoutMs: 400,
    })).rejects.toThrow(/did not listen/);
  });
});

describe('3.6.1 recorded evidence', () => {
  it('prioritizes a finding that was executed and confirmed', () => {
    const [row] = applyRecordedEvidence([finding('ran.js')], ['ran.js'], ['ran.js']);
    expect(row).toMatchObject({ severity: 'high', evidence: 'prioritized' });
    expect(row?.gate).toBeUndefined();
  });

  it('still downgrades a file that was not executed', () => {
    const [row] = applyRecordedEvidence([finding('idle.js')], ['ran.js'], ['idle.js']);
    expect(row).toMatchObject({ severity: 'info', gate: false });
    expect(row?.evidence).toBeUndefined();
  });
});
