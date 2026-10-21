import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { tlsEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_TLS';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file: string; line?: number; severity: string; context?: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file}|${f.line ?? ''}|${f.severity}|${f.context ?? ''}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-tls-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_TLS', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(tlsEnabled()).toBe(false);
    process.env[FLAG] = 'true';
    expect(tlsEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(tlsEnabled()).toBe(true);
  });

  it('reports disabled TLS verification and lowers severity for tests and dev guards', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(
      join(cwd, 'app.js'),
      [
        "const https = require('https');",
        "const tls = require('tls');",
        "const { Agent } = require('undici');",
        "https.request('https://example.test', { rejectUnauthorized: false });",
        "tls.connect(443, { rejectUnauthorized: false });",
        "new https.Agent({ rejectUnauthorized: false });",
        "new Agent({ connect: { rejectUnauthorized: false } });",
        "got('https://example.test', { https: { rejectUnauthorized: false } });",
        "axios.get('https://example.test', { httpsAgent: { rejectUnauthorized: false } });",
        "https.request('https://example.test', { checkServerIdentity: () => undefined });",
        "if (process.env.NODE_ENV !== 'production') { https.get('https://example.test', { rejectUnauthorized: false }); }",
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
      ].join('\n'),
    );
    await mkdir(join(cwd, 'test'));
    await writeFile(join(cwd, 'test', 'app.test.js'), "https.request(url, { rejectUnauthorized: false });\n");
    await writeFile(join(cwd, 'Dockerfile'), 'ENV NODE_TLS_REJECT_UNAUTHORIZED 0\n');
    await writeFile(join(cwd, 'package.json'), '{"scripts":{"start":"NODE_TLS_REJECT_UNAUTHORIZED=0 node app.js"}}\n');
    await writeFile(join(cwd, 'compose.yml'), 'environment:\n  NODE_TLS_REJECT_UNAUTHORIZED: "0"\n');
    await writeFile(join(cwd, '.env'), 'NODE_TLS_REJECT_UNAUTHORIZED=0\n');

    const result = await scan({ cwd, modules: ['sast'], offline: true });
    const app = result.findings.filter((f) => f.file === 'app.js');
    expect(app.filter((f) => f.ruleId === 'SAST-TLS-001' && f.severity === 'high').length).toBeGreaterThanOrEqual(6);
    expect(app.some((f) => f.ruleId === 'SAST-TLS-001' && f.severity === 'medium')).toBe(true);
    expect(app.some((f) => f.ruleId === 'SAST-TLS-002' && f.severity === 'high')).toBe(true);
    const testHit = result.findings.find((f) => f.file === 'test/app.test.js');
    expect(testHit).toMatchObject({ ruleId: 'SAST-TLS-001', severity: 'low', context: 'test' });
    for (const file of ['Dockerfile', 'package.json', 'compose.yml', '.env']) {
      expect(result.findings.some((f) => f.file === file && f.ruleId === 'SAST-TLS-002' && f.severity === 'high')).toBe(true);
    }
  });

  it('does not report verification left on, unresolved options, or a ca pin', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(
      join(cwd, 'ok.js'),
      [
        "https.request(url, { rejectUnauthorized: true });",
        "const opts = { rejectUnauthorized: false }; https.request(url, opts);",
        "https.request(url, { rejectUnauthorized: false, ca: cert });",
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';",
      ].join('\n'),
    );
    await writeFile(join(cwd, '.env.example'), 'NODE_TLS_REJECT_UNAUTHORIZED=1\n');
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    expect(result.findings.filter((f) => f.ruleId === 'SAST-TLS-001' || f.ruleId === 'SAST-TLS-002')).toEqual([]);
  });

  it('stays off the default scan, including vulnerable-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'app.js'), "https.request(url, { rejectUnauthorized: false });\n");
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['sast'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SAST-TLS-001');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
  });

  it('clean-app stays at 0 findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const clean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    expect(clean.findings).toEqual([]);
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'app.js'), "https.request(url, { rejectUnauthorized: false });\n");
    const first = await scan({ cwd, modules: ['sast'], offline: true });
    const second = await scan({ cwd, modules: ['sast'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
  });
});
