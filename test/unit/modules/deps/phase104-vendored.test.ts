import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { vendoredEnabled } from '../../../../src/modules/sast/experimental.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_VENDORED';
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function sig(findings: { ruleId: string; file?: string; line?: number; severity: string }[]) {
  return findings.map((f) => `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.severity}`).sort();
}

async function fixtureDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-vendored-'));
  dirs.push(cwd);
  return cwd;
}

function osv(id: string, severity: string) {
  return JSON.stringify({
    fetchedAt: '2026-10-21T00:00:00.000Z',
    vulns: [{ id, summary: 'fixture', database_specific: { severity }, affected: [] }],
  });
}

afterEach(async () => {
  delete process.env[FLAG];
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('FULLSHIELD_EXPERIMENTAL_VENDORED', () => {
  it('is off unless the env flag is exactly 1', () => {
    delete process.env[FLAG];
    expect(vendoredEnabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(vendoredEnabled()).toBe(true);
  });

  it('maps a banner or VERSION to OSV and ignores a cache miss', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'public'), { recursive: true });
    await mkdir(join(cwd, 'vendor'), { recursive: true });
    await mkdir(join(cwd, 'lib'), { recursive: true });
    await mkdir(join(cwd, 'cache', 'osv'), { recursive: true });
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ name: 'app' }));
    await writeFile(join(cwd, 'package-lock.json'), JSON.stringify({ name: 'app', lockfileVersion: 2, packages: { '': {} } }));
    await writeFile(join(cwd, 'fullshield.config.json'), JSON.stringify({ deps: { cacheDir: 'cache' } }));
    await mkdir(join(cwd, 'assets'), { recursive: true });
    await mkdir(join(cwd, 'static'), { recursive: true });
    await writeFile(join(cwd, 'public', 'jquery.min.js'), '/*! jQuery v3.4.1 | (c) JS Foundation */\n');
    await writeFile(join(cwd, 'public', 'jquery-version.js'), 'jQuery.VERSION = "3.5.1";\n');
    await writeFile(join(cwd, 'public', 'jquery-ui.js'), '/*! jQuery UI - v1.12.1 */\n');
    await writeFile(join(cwd, 'static', 'bootstrap.js'), '/* Bootstrap v3.4.1 */\n');
    await writeFile(join(cwd, 'public', 'angular.js'), '/* AngularJS v1.6.9 */\n');
    await writeFile(join(cwd, 'public', 'ng.js'), '/* angular v12.0.0 */\n');
    await writeFile(join(cwd, 'lib', 'lodash.js'), '/*! Lodash 4.17.15 */\n');
    await writeFile(join(cwd, 'lib', 'underscore.js'), '/* Underscore.js 1.13.1 */\n');
    await writeFile(join(cwd, 'vendor', 'moment.min.js'), '//! Moment.js 2.29.1\n');
    await writeFile(join(cwd, 'assets', 'handlebars.js'), '/* Handlebars v4.7.7 */\n');
    await writeFile(join(cwd, 'assets', 'dompurify.js'), '/* DOMPurify 2.3.0 */\n');
    await writeFile(join(cwd, 'lib', 'knockout.js'), '/* Knockout 3.5.1 */\n');
    await writeFile(join(cwd, 'public', 'plain.js'), 'var app = 1;\n');
    const banners: Array<[string, string]> = [
      ['jquery@3.4.1', 'GHSA-jquery'],
      ['jquery@3.5.1', 'GHSA-jquery-ver'],
      ['jquery-ui@1.12.1', 'GHSA-jquery-ui'],
      ['bootstrap@3.4.1', 'GHSA-bootstrap'],
      ['angular@1.6.9', 'GHSA-angular'],
      ['@angular/core@12.0.0', 'GHSA-ng'],
      ['lodash@4.17.15', 'GHSA-lodash'],
      ['underscore@1.13.1', 'GHSA-underscore'],
      ['handlebars@4.7.7', 'GHSA-handlebars'],
      ['dompurify@2.3.0', 'GHSA-dompurify'],
      ['knockout@3.5.1', 'GHSA-knockout'],
    ];
    for (const [spec, id] of banners) {
      const file = `${spec.replaceAll('/', '__')}.json`;
      await writeFile(join(cwd, 'cache', 'osv', file), osv(id, 'HIGH'));
    }
    const result = await scan({ cwd, modules: ['deps'], offline: true });
    const vendored = result.findings.filter((f) => f.ruleId === 'DEPS-VENDORED-001');
    expect(vendored.map((f) => f.file).sort()).toEqual([
      'assets/dompurify.js',
      'assets/handlebars.js',
      'lib/knockout.js',
      'lib/lodash.js',
      'lib/underscore.js',
      'public/angular.js',
      'public/jquery-ui.js',
      'public/jquery-version.js',
      'public/jquery.min.js',
      'public/ng.js',
      'static/bootstrap.js',
    ]);
    expect(vendored.every((f) => f.reachability === 'vendored')).toBe(true);
    expect(vendored.find((f) => f.file === 'public/jquery.min.js')).toMatchObject({ severity: 'high' });
    expect(vendored.find((f) => f.file === 'lib/lodash.js')).toMatchObject({ severity: 'high' });
    expect(vendored.every((f) => f.remediation.includes('Replace') && !f.remediation.includes('npm install'))).toBe(true);
    expect(vendored.some((f) => f.file === 'vendor/moment.min.js' || f.file === 'public/plain.js')).toBe(false);
  });

  it('stays off the default scan, including vulnerable-app and clean-app', async () => {
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'public'), { recursive: true });
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ name: 'app' }));
    await writeFile(join(cwd, 'package-lock.json'), JSON.stringify({ name: 'app', lockfileVersion: 2, packages: { '': {} } }));
    await writeFile(join(cwd, 'public', 'jquery.js'), '/*! jQuery v1.2.3 */\n');
    delete process.env[FLAG];
    const offFixture = await scan({ cwd, modules: ['deps'], offline: true });
    const offApp = await scan({ cwd: vulnerableApp, modules: ['deps'], offline: true });
    const offClean = await scan({ cwd: cleanApp, modules: ['deps'], offline: true });
    process.env[FLAG] = '1';
    const onApp = await scan({ cwd: vulnerableApp, modules: ['deps'], offline: true });
    const onClean = await scan({ cwd: cleanApp, modules: ['deps'], offline: true });
    expect(offFixture.findings.map((f) => f.ruleId)).not.toContain('DEPS-VENDORED-001');
    expect(sig(onApp.findings)).toEqual(sig(offApp.findings));
    expect(sig(onClean.findings)).toEqual(sig(offClean.findings));
  });

  it('is deterministic across two scans', async () => {
    process.env[FLAG] = '1';
    const cwd = await fixtureDir();
    await mkdir(join(cwd, 'static'), { recursive: true });
    await mkdir(join(cwd, 'cache', 'osv'), { recursive: true });
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ name: 'app' }));
    await writeFile(join(cwd, 'package-lock.json'), JSON.stringify({ name: 'app', lockfileVersion: 2, packages: { '': {} } }));
    await writeFile(join(cwd, 'fullshield.config.json'), JSON.stringify({ deps: { cacheDir: 'cache' } }));
    await writeFile(join(cwd, 'static', 'bootstrap.js'), '/* Bootstrap v3.3.7 */\n');
    await writeFile(join(cwd, 'cache', 'osv', 'bootstrap@3.3.7.json'), osv('GHSA-bootstrap', 'MEDIUM'));
    const first = await scan({ cwd, modules: ['deps'], offline: true });
    const second = await scan({ cwd, modules: ['deps'], offline: true });
    expect(sig(second.findings)).toEqual(sig(first.findings));
    expect(first.findings.some((f) => f.ruleId === 'DEPS-VENDORED-001' && f.severity === 'medium')).toBe(true);
  });
});
