import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { scanLicensePolicy } from '../../../src/modules/deps/license-policy.js';

const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_LICENSE_POLICY;
  delete process.env.FULLSHIELD_EXPERIMENTAL_PRIVATE_REG;
  delete process.env.FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL;
  delete process.env.FULLSHIELD_EXPERIMENTAL_EXCEPTIONS;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function project(license: unknown, lists: { deny?: string[]; allow?: string[] }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-license-'));
  dirs.push(dir);
  await writeFile(join(dir, 'package.json'), JSON.stringify({ dependencies: { leftpad: '1.0.0' } }), 'utf8');
  await mkdir(join(dir, 'node_modules', 'leftpad'), { recursive: true });
  await writeFile(
    join(dir, 'node_modules', 'leftpad', 'package.json'),
    JSON.stringify({ name: 'leftpad', version: '1.0.0', license }),
    'utf8',
  );
  if (lists.deny !== undefined || lists.allow !== undefined) {
    process.env.FULLSHIELD_EXPERIMENTAL_LICENSE_POLICY = '1';
    await writeFile(
      join(dir, 'fullshield.config.json'),
      JSON.stringify({ deps: { offline: true, licenseDeny: lists.deny, licenseAllow: lists.allow } }),
      'utf8',
    );
  }
  return dir;
}

describe('phase 558 license policy', () => {
  it('fires a deny hit and says it is a policy, not a vulnerability', async () => {
    const dir = await project('GPL-3.0', { deny: ['gpl-3.0'] });
    const findings = await scanLicensePolicy(dir, { deny: ['gpl-3.0'] });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('DEPS-LICENSE-002');
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.message).toMatch(/license policy, not a vulnerability/);
  });

  it('lets an allow entry suppress the same deny string', async () => {
    const dir = await project('GPL-3.0', { deny: ['GPL-3.0'], allow: ['gpl-3.0'] });
    expect(await scanLicensePolicy(dir, { deny: ['GPL-3.0'], allow: ['gpl-3.0'] })).toEqual([]);
  });

  it('fires when a known license is on neither list and the allow list is non-empty', async () => {
    const dir = await project('MIT', { allow: ['Apache-2.0'] });
    const findings = await scanLicensePolicy(dir, { allow: ['Apache-2.0'] });
    expect(findings.map((row) => row.ruleId)).toEqual(['DEPS-LICENSE-002']);
  });

  it('stays silent when the license is missing or the lists are empty', async () => {
    const missing = await project(undefined, {});
    expect(await scanLicensePolicy(missing, { deny: ['GPL-3.0'], allow: ['MIT'] })).toEqual([]);
    const empty = await project('GPL-3.0', {});
    expect(await scanLicensePolicy(empty, {})).toEqual([]);
    expect(await scanLicensePolicy(empty, { deny: [], allow: [] })).toEqual([]);
  });

  it('reads an object license and skips a package.json it cannot read', async () => {
    const dir = await project({ type: 'GPL-3.0' }, { deny: ['gpl-3.0'] });
    expect((await scanLicensePolicy(dir, { deny: ['gpl-3.0'] })).map((row) => row.ruleId)).toEqual(['DEPS-LICENSE-002']);
    await rm(join(dir, 'node_modules', 'leftpad', 'package.json'));
    await mkdir(join(dir, 'node_modules', 'leftpad', 'package.json'));
    expect(await scanLicensePolicy(dir, { deny: ['gpl-3.0'] })).toEqual([]);
  });

  it('ignores the lists when the flag is off', async () => {
    const dir = await project('GPL-3.0', {});
    delete process.env.FULLSHIELD_EXPERIMENTAL_LICENSE_POLICY;
    await writeFile(
      join(dir, 'fullshield.config.json'),
      JSON.stringify({ deps: { offline: true, licenseDeny: ['GPL-3.0'] } }),
      'utf8',
    );
    const result = await scan({ cwd: dir, modules: ['deps'], offline: true });
    expect(result.findings.some((row) => row.ruleId === 'DEPS-LICENSE-002')).toBe(false);
  });

  it('clean-app stays free of the new dependency rules with the flags on', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_LICENSE_POLICY = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_PRIVATE_REG = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_EXCEPTIONS = '1';
    const cache = await mkdtemp(join(tmpdir(), 'fullshield-empty-cache-'));
    dirs.push(cache);
    const configDir = await mkdtemp(join(tmpdir(), 'fullshield-clean-cfg-'));
    dirs.push(configDir);
    const configPath = join(configDir, 'fullshield.config.json');
    await writeFile(configPath, JSON.stringify({ deps: { offline: true, cacheDir: cache } }), 'utf8');
    const result = await scan({
      cwd: join(rootOf(), 'test/fixtures/clean-app'),
      modules: ['deps'],
      offline: true,
      configPath,
    });
    expect(result.findings.filter((row) => row.ruleId === 'DEPS-LICENSE-002' || row.ruleId === 'DEPS-ORG-ADV-001')).toEqual([]);
    expect(result.findings.filter((row) => row.severity === 'high' || row.severity === 'critical')).toEqual([]);
  });
});

function rootOf(): string {
  return join(import.meta.dirname, '../../..');
}
