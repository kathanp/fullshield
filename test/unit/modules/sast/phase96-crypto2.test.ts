import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { crypto2Enabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_CRYPTO2';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];
const LONG = 'a'.repeat(32);

function sig(findings: { ruleId: string; file: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file}|${f.line ?? ''}|${f.severity}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-crypto2-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_CRYPTO2', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(crypto2Enabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(crypto2Enabled()).toBe(true);
  });

  it('reports weak ciphers, literal keys, short RSA, and JWTs without expiry', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'test'));
    await writeFile(
      join(cwd, 'app.js'),
      [
        "crypto.createCipheriv('aes-256-ecb', key, iv);",
        "crypto.createCipher('aes256', key);",
        "crypto.createCipheriv('aes-256-gcm', key, Buffer.alloc(16));",
        "crypto.createCipheriv('aes-256-gcm', 'literal-key', crypto.randomBytes(16));",
        "crypto.generateKeyPair('rsa', { modulusLength: 1024 });",
        "crypto.generateKeyPair('ec', { namedCurve: 'secp192k1' });",
        "jwt.sign(payload, secret);",
        `jwt.sign(payload, 'short-secret', { expiresIn: '1h' });`,
      ].join('\n'),
    );
    await writeFile(join(cwd, 'test', 'crypto.test.js'), "crypto.createCipheriv('aes-128-ecb', key, iv);\n");
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    const ids = (id: string) => result.findings.filter((f) => f.ruleId === id && f.file === 'app.js');
    expect(ids('SAST-CIPHER-001').length).toBeGreaterThanOrEqual(3);
    expect(ids('SAST-CIPHER-002')).toHaveLength(1);
    expect(ids('SAST-RSA-001').every((f) => f.severity === 'medium')).toBe(true);
    expect(ids('SAST-RSA-001')).toHaveLength(2);
    expect(ids('SAST-JWT-002').length).toBeGreaterThanOrEqual(2);
    const testHit = result.findings.find((f) => f.file === 'test/crypto.test.js');
    expect(testHit).toMatchObject({ ruleId: 'SAST-CIPHER-001', severity: 'low', context: 'test' });
  });

  it('reports exactly one finding when a literal key shares a line with a secret rule', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'app.js'), "crypto.createHmac('sha256', 'jwt-secret-value');\n");
    const result = await scan({ cwd, modules: ['sast', 'secrets'], offline: true });
    const line = result.findings.filter((f) =>
      f.line === 1 && ['SAST-CIPHER-002', 'SECRET-JWT-001', 'SECRET-ENTROPY-001'].includes(f.ruleId),
    );
    expect(line).toHaveLength(1);
  });

  it('does not report random IVs, aes-256-gcm, env keys, or a long JWT secret with expiry', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(
      join(cwd, 'ok.js'),
      [
        "crypto.createCipheriv('aes-256-gcm', process.env.KEY, crypto.randomBytes(16));",
        "crypto.generateKeyPair('rsa', { modulusLength: 2048 });",
        `jwt.sign(payload, '${LONG}', { expiresIn: '1h' });`,
      ].join('\n'),
    );
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    expect(result.findings.filter((f) => f.ruleId.startsWith('SAST-CIPHER') || f.ruleId === 'SAST-RSA-001' || f.ruleId === 'SAST-JWT-002')).toEqual([]);
  });

  it('stays off the default scan, including vulnerable-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'app.js'), "crypto.createCipheriv('aes-256-ecb', key, iv);\n");
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['sast'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SAST-CIPHER-001');
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
    await writeFile(join(cwd, 'app.js'), "crypto.createCipher('aes256', key);\n");
    const first = await scan({ cwd, modules: ['sast'], offline: true });
    const second = await scan({ cwd, modules: ['sast'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
  });
});
