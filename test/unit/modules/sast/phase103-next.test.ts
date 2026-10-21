import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { nextEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_NEXT';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-next-'));
  dirs.push(cwd);
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_NEXT', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(nextEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(nextEnabled()).toBe(true);
  });

  it('reports an unauthenticated server action, middleware-only auth, open images, and a public secret name', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'app'), { recursive: true });
    await writeFile(join(cwd, 'action.js'), "'use server';\nasync function save(data) { await db.query(data); }\n");
    await writeFile(join(cwd, 'helper.js'), "'use server';\nasync function save(data) { await writeRow(data); }\nasync function writeRow(data) { await db.query(data); }\n");
    await writeFile(join(cwd, 'helper-auth.js'), "'use server';\nasync function save(data) { await writeRow(data); }\nasync function writeRow(data) { await auth(); await db.query(data); }\n");
    await writeFile(join(cwd, 'authed.js'), "'use server';\nasync function save(data) { await auth(); await db.query(data); }\n");
    await writeFile(
      join(cwd, 'middleware.ts'),
      "export const config = { matcher: ['/app/:path*'] };\nexport function middleware() { return auth(); }\n",
    );
    await writeFile(join(cwd, 'app', 'page.js'), 'function Page() { return null; }\n');
    await writeFile(
      join(cwd, 'next.config.js'),
      "module.exports = { images: { remotePatterns: [{ hostname: '**' }] } };\n",
    );
    await writeFile(join(cwd, '.env'), 'NEXT_PUBLIC_SECRET_TOKEN=example\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_example\n');
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    expect(result.findings.filter((f) => f.ruleId === 'SAST-NEXT-001' && f.file === 'action.js')).toHaveLength(1);
    expect(result.findings.filter((f) => f.ruleId === 'SAST-NEXT-001' && f.file === 'helper.js').length).toBeGreaterThan(0);
    expect(result.findings.filter((f) => f.ruleId === 'SAST-NEXT-001' && f.file === 'helper-auth.js')).toHaveLength(0);
    expect(result.findings.filter((f) => f.ruleId === 'SAST-NEXT-001' && f.file === 'authed.js')).toHaveLength(0);
    const middleware = result.findings.find((f) => f.ruleId === 'CONFIG-NEXT-001');
    expect(middleware?.severity).toBe('info');
    expect(middleware?.message).toMatch(/2025 middleware-bypass/);
    expect(middleware?.message).toMatch(/handler/);
    expect(result.findings.some((f) => f.ruleId === 'CONFIG-NEXT-002')).toBe(true);
    const pub = result.findings.filter((f) => f.ruleId === 'SECRET-NEXTPUB-001');
    expect(pub).toHaveLength(1);
    expect(pub[0]?.message).toContain('NEXT_PUBLIC_SECRET_TOKEN');
    expect(pub[0]?.severity).toBe('high');
  });

  it('does not report middleware auth when the handler also checks auth', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'app'), { recursive: true });
    await writeFile(join(cwd, 'middleware.ts'), 'export const config = { matcher: ["/"] };\nexport function middleware() { return auth(); }\n');
    await writeFile(join(cwd, 'app', 'page.js'), 'function Page() { return auth(); }\n');
    await writeFile(join(cwd, 'next.config.js'), "module.exports = { images: { domains: ['cdn.example'] } };\n");
    const result = await scan({ cwd, modules: ['sast'], offline: true });
    expect(result.findings.filter((f) => f.ruleId === 'CONFIG-NEXT-001' || f.ruleId === 'CONFIG-NEXT-002')).toEqual([]);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'action.js'), "'use server';\nasync function save(data) { await db.update(data); }\n");
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['sast'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['sast'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['sast'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('SAST-NEXT-001');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'action.js'), "'use server';\nasync function save(data) { await db.create(data); }\n");
    const first = await scan({ cwd, modules: ['sast'], offline: true });
    const second = await scan({ cwd, modules: ['sast'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'SAST-NEXT-001')).toBe(true);
  });
});
