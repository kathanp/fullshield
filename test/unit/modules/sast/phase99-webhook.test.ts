import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { webhookEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_WEBHOOK';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-webhook-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_WEBHOOK', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(webhookEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(webhookEnabled()).toBe(true);
  });

  it('reports a known provider with no verifier and ignores a verified or unknown provider', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(
      join(cwd, 'stripe.js'),
      "app.post('/hook', (req, res) => { const type = req.body.event.type; res.send(type); });\n",
    );
    await writeFile(
      join(cwd, 'verified.js'),
      "app.post('/hook', (req, res) => { stripe.webhooks.constructEvent(req.body, sig, secret); res.send(req.body.event.type); });\n",
    );
    await writeFile(
      join(cwd, 'unknown.js'),
      "app.post('/hook', (req, res) => { const ev = req.headers['x-custom-vendor']; res.send(ev); });\n",
    );
    await writeFile(
      join(cwd, 'github.js'),
      "app.post('/hook', (req, res) => { const ev = req.headers['x-github-event']; res.send(ev); });\n",
    );
    await writeFile(
      join(cwd, 'mounted.js'),
      "function verifyGitHub(req, res, next) { timingSafeEqual(a, b); next(); }\napp.use('/events', verifyGitHub);\n",
    );
    await writeFile(
      join(cwd, 'hooks.js'),
      "app.post('/events', (req, res) => { res.send(req.headers['x-github-event']); });\n",
    );
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    const hits = result.findings.filter((f) => f.ruleId === 'SAST-WEBHOOK-001');
    expect(hits.map((f) => f.file).sort()).toEqual(['github.js', 'stripe.js']);
    expect(hits.every((f) => f.severity === 'high')).toBe(true);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'stripe.js'), "app.post('/hook', (req, res) => { res.send(req.body.event.type); });\n");
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['sast'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SAST-WEBHOOK-001');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'slack.js'), "app.post('/hook', (req, res) => { res.send(req.headers['x-slack-signature']); });\n");
    const first = await scan({ cwd, modules: ['sast'], offline: true });
    const second = await scan({ cwd, modules: ['sast'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'SAST-WEBHOOK-001')).toBe(true);
  });
});
