import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { credFilesEnabled } from '../../../../src/modules/secrets/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_CREDFILES';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

const TOKEN = 'npm_' + 'fakeTokenValue123456';
const DOCKER_AUTH = 'ZG9j' + 'a2VyOmZha2U=';
const KUBE_TOKEN = 'kube' + 'token-fake-value';
const KEY_B64 = 'LS0t' + 'FAKEPRIVATEKEYDATA';
const PEM = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\n' + 'ZmFr' + 'ZWtleQ==\n-----END OPENSSH PRIVATE KEY-----';

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string; snippet?: string }[]) {
  return findings
    .map((f) => `${f.ruleId}|${f.file}|${f.line}|${f.severity}|${f.snippet ?? ''}`)
    .sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-cred-'));
  dirs.push(cwd);
  return cwd;
}

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' });
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_CREDFILES', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(credFilesEnabled()).toBe(false);
    process.env[FLAG] = 'true';
    expect(credFilesEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(credFilesEnabled()).toBe(true);
  });

  it('reports each committed credential file and masks the secret', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await mkdir(join(cwd, '.docker'), { recursive: true });
    await writeFile(join(cwd, '.npmrc'), `//registry.example.test/:_authToken=${TOKEN}\n_auth=${'basic' + 'LiteralValue'}\n`);
    await writeFile(
      join(cwd, '.docker', 'config.json'),
      `{"auths":{"https://example.test":{"auth":"${DOCKER_AUTH}"}}}\n`,
    );
    await writeFile(
      join(cwd, 'kubeconfig'),
      `apiVersion: v1\nkind: Config\nusers:\n- name: u\n  user:\n    token: ${KUBE_TOKEN}\n`,
    );
    await writeFile(join(cwd, 'app.tfstate'), '{}\n');
    await writeFile(join(cwd, 'app.tfstate.backup'), '{}\n');
    await writeFile(
      join(cwd, 'sa.json'),
      `{"type":"service_account","private_key":"${KEY_B64}"}\n`,
    );
    await writeFile(join(cwd, 'id_rsa'), PEM);
    await writeFile(join(cwd, 'id_ed25519'), PEM);
    await writeFile(join(cwd, 'store.p12'), Buffer.from([0x30, 0x00, 0x01]));
    await writeFile(join(cwd, 'store.pfx'), Buffer.from([0x30, 0x00, 0x02]));
    await writeFile(join(cwd, 'store.keystore'), Buffer.from([0x30, 0x00, 0x03]));

    const result = await scan({ cwd, modules: ['secrets'], offline: true });
    const byId = (id: string) => result.findings.filter((f) => f.ruleId === id);

    expect(byId('SECRET-FILE-002').map((f) => f.line).sort()).toEqual([1, 2]);
    expect(byId('SECRET-FILE-002').every((f) => f.severity === 'critical' && f.file === '.npmrc')).toBe(true);
    expect(byId('SECRET-FILE-002').every((f) => f.snippet?.includes('****') && !f.snippet.includes(TOKEN))).toBe(true);

    const docker = byId('SECRET-FILE-003');
    expect(docker).toHaveLength(1);
    expect(docker[0]).toMatchObject({ file: '.docker/config.json', severity: 'critical' });
    expect(docker[0]?.snippet?.endsWith('****')).toBe(true);
    expect(docker[0]?.snippet).not.toContain(DOCKER_AUTH);

    const kube = byId('SECRET-FILE-004');
    expect(kube).toHaveLength(1);
    expect(kube[0]).toMatchObject({ file: 'kubeconfig', severity: 'critical' });
    expect(kube[0]?.snippet).not.toContain(KUBE_TOKEN);

    expect(byId('SECRET-FILE-005').map((f) => `${f.file}|${f.severity}`).sort()).toEqual([
      'app.tfstate.backup|high',
      'app.tfstate|high',
    ]);

    const sa = byId('SECRET-FILE-006');
    expect(sa).toHaveLength(1);
    expect(sa[0]).toMatchObject({ file: 'sa.json', severity: 'critical' });
    expect(sa[0]?.snippet).not.toContain(KEY_B64);

    const keys = byId('SECRET-FILE-007').map((f) => f.file).sort();
    expect(keys).toEqual(['id_ed25519', 'id_rsa', 'store.keystore', 'store.p12', 'store.pfx']);
    expect(byId('SECRET-FILE-007').every((f) => f.severity === 'critical')).toBe(true);
  });

  it('does not report placeholders, public keys, or empty auth', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, '.npmrc'), '_authToken=${NPM_TOKEN}\n');
    await writeFile(join(cwd, 'config.json'), '{"auths":{"https://example.test":{"auth":""}}}\n');
    await writeFile(join(cwd, 'plain.yaml'), 'kind: Config\ntoken: nope\n');
    await writeFile(join(cwd, 'sa.json'), '{"type":"service_account","private_key":""}\n');
    await writeFile(join(cwd, 'id_rsa.pub'), 'ssh-ed25519 AAAA comment\n');
    await writeFile(join(cwd, 'notes.txt'), 'no credentials here\n');

    const result = await scan({ cwd, modules: ['secrets'], offline: true });
    const ids = result.findings.map((f) => f.ruleId);
    for (const id of ['SECRET-FILE-002', 'SECRET-FILE-003', 'SECRET-FILE-004', 'SECRET-FILE-005', 'SECRET-FILE-006', 'SECRET-FILE-007']) {
      expect(ids).not.toContain(id);
    }
  });

  it('stays off the default scan, including vulnerable-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, '.npmrc'), `//registry.example.test/:_authToken=${TOKEN}\n`);
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['secrets'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['secrets'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['secrets'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SECRET-FILE-002');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
  });

  it('clean-app stays at 0 findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const clean = await scan({ cwd: cleanApp, offline: true });
    expect(clean.findings).toEqual([]);
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, '.npmrc'), `_auth=${'basic' + 'LiteralValue'}\n`);
    const first = await scan({ cwd, modules: ['secrets'], offline: true });
    const second = await scan({ cwd, modules: ['secrets'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'SECRET-FILE-002')).toBe(true);
  });

  it('covers staged files and ignores unstaged credential files', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    git(cwd, 'init', '--quiet');
    git(cwd, 'config', 'user.email', 'test@example.com');
    git(cwd, 'config', 'user.name', 'Test');
    git(cwd, 'config', 'commit.gpgsign', 'false');
    await writeFile(join(cwd, '.npmrc'), `//registry.example.test/:_authToken=${TOKEN}\n`);
    await writeFile(join(cwd, 'kubeconfig'), `apiVersion: v1\nkind: Config\n    token: ${KUBE_TOKEN}\n`);
    git(cwd, 'add', '.npmrc');
    const result = await scan({ cwd, modules: ['secrets'], offline: true, staged: true });
    expect(result.findings.map((f) => f.ruleId)).toContain('SECRET-FILE-002');
    expect(result.findings.map((f) => f.ruleId)).not.toContain('SECRET-FILE-004');
  });
});
