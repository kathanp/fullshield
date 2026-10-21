import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { isActionable } from '../../../../src/reporters/console.js';
import { healthEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_HEALTH';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

function lock(field: 'dependencies' | 'devDependencies'): string {
  return JSON.stringify({
    name: 'app',
    lockfileVersion: 2,
    packages: {
      '': { [field]: { oldlib: '1.2.3' } },
      'node_modules/oldlib': { version: '1.2.3' },
    },
  });
}

function vuln(fixed?: string): string {
  const events = fixed === undefined ? [{ introduced: '0' }] : [{ introduced: '0' }, { fixed }];
  return JSON.stringify({
    fetchedAt: '2026-10-21T00:00:00.000Z',
    vulns: [{
      id: 'GHSA-old-unfixed',
      summary: 'no fix shipped',
      affected: [{ ranges: [{ type: 'ECOSYSTEM', events }] }],
    }],
  });
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-health-'));
  dirs.push(cwd);
  await mkdir(join(cwd, 'cache', 'osv'), { recursive: true });
  await mkdir(join(cwd, 'cache', 'registry'), { recursive: true });
  await writeFile(join(cwd, 'fullshield.config.json'), JSON.stringify({ deps: { cacheDir: 'cache' } }));
  await writeFile(join(cwd, 'cache', 'osv', 'oldlib@1.2.3.json'), vuln());
  return cwd;
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_HEALTH', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(healthEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(healthEnabled()).toBe(true);
  });

  it('reports a stale production dependency with no fixed version, and folds it unless reachable', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { oldlib: '1.2.3' } }));
    await writeFile(join(cwd, 'package-lock.json'), lock('dependencies'));
    await writeFile(
      join(cwd, 'cache', 'registry', 'oldlib.json'),
      JSON.stringify({ fetchedAt: '2026-10-21T00:00:00.000Z', packument: { time: { '1.2.3': '2020-01-01T00:00:00.000Z' }, versions: { '1.2.3': {} } } }),
    );
    const unused = await scan({ cwd, modules: ['deps'], offline: true });
    const folded = unused.findings.find((f) => f.ruleId === 'DEPS-UNFIXED-001');
    expect(folded).toMatchObject({ severity: 'medium', reachability: 'not-imported' });
    expect(folded?.remediation).toMatch(/does not name a replacement/);
    expect(folded?.remediation).not.toMatch(/oldlib|lodash|npm install/i);
    expect(isActionable(folded!)).toBe(false);
    await writeFile(join(cwd, 'app.js'), "const oldlib = require('oldlib');\noldlib.run();\n");
    const used = await scan({ cwd, modules: ['deps'], offline: true });
    const shown = used.findings.find((f) => f.ruleId === 'DEPS-UNFIXED-001');
    expect(shown?.reachability).toBe('reachable');
    expect(isActionable(shown!)).toBe(true);
  });

  it('skips a fixed advisory, a dev dependency, and an unknown publish date', async () => {
    process.env[FLAG] = '1';
    const dated = await fixtureDir();
    await writeFile(join(dated, 'package.json'), JSON.stringify({ dependencies: { oldlib: '1.2.3' } }));
    await writeFile(join(dated, 'package-lock.json'), lock('dependencies'));
    await writeFile(join(dated, 'cache', 'osv', 'oldlib@1.2.3.json'), vuln('1.2.4'));
    await writeFile(
      join(dated, 'cache', 'registry', 'oldlib.json'),
      JSON.stringify({ fetchedAt: '2026-10-21T00:00:00.000Z', packument: { time: { '1.2.3': '2020-01-01T00:00:00.000Z' }, versions: {} } }),
    );
    const dev = await fixtureDir();
    await writeFile(join(dev, 'package.json'), JSON.stringify({ devDependencies: { oldlib: '1.2.3' } }));
    await writeFile(join(dev, 'package-lock.json'), lock('devDependencies'));
    await writeFile(
      join(dev, 'cache', 'registry', 'oldlib.json'),
      JSON.stringify({ fetchedAt: '2026-10-21T00:00:00.000Z', packument: { time: { '1.2.3': '2020-01-01T00:00:00.000Z' }, versions: {} } }),
    );
    const unknown = await fixtureDir();
    await writeFile(join(unknown, 'package.json'), JSON.stringify({ dependencies: { oldlib: '1.2.3' } }));
    await writeFile(join(unknown, 'package-lock.json'), lock('dependencies'));
    await writeFile(join(unknown, 'cache', 'registry', 'oldlib.json'), JSON.stringify({ fetchedAt: '2026-10-21T00:00:00.000Z', packument: { versions: {} } }));
    const fixed = await scan({ cwd: dated, modules: ['deps'], offline: true });
    const devOnly = await scan({ cwd: dev, modules: ['deps'], offline: true });
    const noDate = await scan({ cwd: unknown, modules: ['deps'], offline: true });
    expect(fixed.findings.filter((f) => f.ruleId === 'DEPS-UNFIXED-001')).toEqual([]);
    expect(devOnly.findings.filter((f) => f.ruleId === 'DEPS-UNFIXED-001')).toEqual([]);
    expect(noDate.findings.filter((f) => f.ruleId === 'DEPS-UNFIXED-001')).toEqual([]);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    const cache = join(cwd, 'empty-cache');
    await mkdir(cache, { recursive: true });
    const configPath = join(cwd, 'scan-config.json');
    await writeFile(configPath, JSON.stringify({ deps: { cacheDir: cache } }));
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { oldlib: '1.2.3' } }));
    await writeFile(join(cwd, 'package-lock.json'), lock('dependencies'));
    await writeFile(
      join(cwd, 'cache', 'registry', 'oldlib.json'),
      JSON.stringify({ fetchedAt: '2026-10-21T00:00:00.000Z', packument: { time: { '1.2.3': '2020-01-01T00:00:00.000Z' }, versions: {} } }),
    );
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['deps'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['deps'], offline: true, configPath });
    const offClean = await scan({ cwd: cleanApp, modules: ['deps'], offline: true, configPath });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['deps'], offline: true, configPath });
    const onClean = await scan({ cwd: cleanApp, modules: ['deps'], offline: true, configPath });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('DEPS-UNFIXED-001');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { oldlib: '1.2.3' } }));
    await writeFile(join(cwd, 'package-lock.json'), lock('dependencies'));
    await writeFile(
      join(cwd, 'cache', 'registry', 'oldlib.json'),
      JSON.stringify({ fetchedAt: '2026-10-21T00:00:00.000Z', packument: { time: { '1.2.3': '2020-01-01T00:00:00.000Z' }, versions: {} } }),
    );
    const first = await scan({ cwd, modules: ['deps'], offline: true });
    const second = await scan({ cwd, modules: ['deps'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'DEPS-UNFIXED-001')).toBe(true);
  });
});
