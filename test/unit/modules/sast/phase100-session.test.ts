import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { session2Enabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SESSION2';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

function lock(version: string): string {
  return JSON.stringify({
    name: 'app',
    lockfileVersion: 2,
    packages: {
      '': { dependencies: { passport: version } },
      'node_modules/passport': { version },
    },
  });
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-session-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_SESSION2', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(session2Enabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(session2Enabled()).toBe(true);
  });

  it('reports a login write without regenerate, and an old passport req.login', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'package-lock.json'), lock('0.5.0'));
    await writeFile(join(cwd, 'login.js'), "app.post('/login', (req, res) => { req.session.user = req.body.user; });\n");
    await writeFile(
      join(cwd, 'regenerated.js'),
      "app.post('/login', (req, res) => { req.session.regenerate(() => { req.session.user = req.body.user; }); });\n",
    );
    await writeFile(join(cwd, 'passport.js'), "app.post('/login', (req, res) => { req.login(user, () => {}); });\n");
    const old = await scan({ cwd, modules: ['sast'], offline: true });
    const hits = old.findings.filter((f) => f.ruleId === 'SAST-SESSION-002');
    expect(hits.map((f) => f.file).sort()).toEqual(['login.js', 'passport.js']);
    expect(hits.find((f) => f.file === 'passport.js')?.message).toContain('0.5.0');
    await writeFile(join(cwd, 'package-lock.json'), lock('0.6.0'));
    const newer = await scan({ cwd, modules: ['sast'], offline: true });
    expect(newer.findings.filter((f) => f.ruleId === 'SAST-SESSION-002').map((f) => f.file)).toEqual(['login.js']);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'login.js'), "app.post('/login', (req, res) => { req.session.userId = id; });\n");
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['sast'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SAST-SESSION-002');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'login.js'), "app.post('/login', (req, res) => { req.session.uid = id; });\n");
    const first = await scan({ cwd, modules: ['sast'], offline: true });
    const second = await scan({ cwd, modules: ['sast'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'SAST-SESSION-002')).toBe(true);
  });
});
