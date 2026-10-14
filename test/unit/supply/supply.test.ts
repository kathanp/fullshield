import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  analyzePackageDir,
  assertRegistryUrl,
  checkCooldown,
  checkDependencyConfusion,
  checkLockfileIntegrity,
  checkProvenance,
  diffPackageVersions,
  installGuard,
  packageNameFromSpec,
} from '../../../src/supply/index.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures/supply');

describe('Phase 19 supply-chain (static, experimental)', () => {
  it('detects a seeded package with an install script that reads .npmrc and calls the network', () => {
    const findings = analyzePackageDir(join(fixtures, 'malicious-pkg'));
    expect(findings.some((f) => f.ruleId === 'SUPPLY-INSTALLSCRIPT-001')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'SUPPLY-NPMRC-NET-001')).toBe(true);
  });

  it('does not flag a benign package without install scripts or exfil patterns', () => {
    const findings = analyzePackageDir(join(fixtures, 'benign-pkg'));
    expect(findings.filter((f) => f.severity === 'high' || f.severity === 'critical')).toHaveLength(0);
  });

  it('version-diffs a newly added postinstall / child_process hook', () => {
    const findings = diffPackageVersions(join(fixtures, 'pkg-v1'), join(fixtures, 'pkg-v2'));
    expect(findings.some((f) => f.ruleId === 'SUPPLY-BEHAVIOR-001')).toBe(true);
  });

  it('refuses any registry host other than registry.npmjs.org', () => {
    expect(() => assertRegistryUrl('https://registry.npmjs.org/lodash')).not.toThrow();
    expect(() => assertRegistryUrl('https://evil.example/lodash')).toThrow(/registry.npmjs.org/);
    expect(() => assertRegistryUrl('https://registry.yarnpkg.com/lodash')).toThrow(/registry.npmjs.org/);
  });

  it('installGuard analyzes a mocked registry tarball and never runs scripts', async () => {
    const ran: string[] = [];
    const result = await installGuard('fullshield-seeded-malicious', {
      experimental: true,
      extractDir: join(fixtures, 'malicious-pkg'),
      fetchPackument: (url) => {
        assertRegistryUrl(url);
        return Promise.resolve({ name: 'fullshield-seeded-malicious', versions: { '1.0.0': {} } });
      },
      runNpm: (args) => {
        ran.push(args.join(' '));
        return Promise.resolve();
      },
    });
    expect(result.findings.some((f) => f.ruleId === 'SUPPLY-NPMRC-NET-001')).toBe(true);
    expect(ran).toEqual([]);
  });

  it('installGuard is a no-op without experimental', async () => {
    const result = await installGuard('lodash', { extractDir: join(fixtures, 'benign-pkg') });
    expect(result.skipped).toBe(true);
    expect(result.findings).toEqual([]);
  });

  it('installGuard runs npm install --ignore-scripts only after a clean static check', async () => {
    const ran: string[] = [];
    const result = await installGuard('fullshield-seeded-benign', {
      experimental: true,
      extractDir: join(fixtures, 'benign-pkg'),
      fetchPackument: (url) => {
        expect(url).toBe('https://registry.npmjs.org/fullshield-seeded-benign');
        return Promise.resolve({});
      },
      runNpm: (args) => {
        ran.push(args.join(' '));
        return Promise.resolve();
      },
    });
    expect(result.findings).toEqual([]);
    expect(ran).toEqual(['install fullshield-seeded-benign --ignore-scripts']);
  });

  it('parses scoped and versioned package specs', () => {
    expect(packageNameFromSpec('lodash@4.17.21')).toBe('lodash');
    expect(packageNameFromSpec('@scope/pkg@1.0.0')).toBe('@scope/pkg');
    expect(packageNameFromSpec('@scope/pkg')).toBe('@scope/pkg');
  });

  it('flags a version published inside the cooldown window', () => {
    const now = Date.parse('2026-10-14T12:00:00Z');
    const hit = checkCooldown(
      { time: { '9.9.9': '2026-10-14T10:00:00Z' } },
      '9.9.9',
      72,
      now,
    );
    expect(hit.some((f) => f.ruleId === 'SUPPLY-COOLDOWN-001')).toBe(true);
    const old = checkCooldown(
      { time: { '1.0.0': '2026-01-01T00:00:00Z' } },
      '1.0.0',
      72,
      now,
    );
    expect(old).toEqual([]);
  });

  it('flags lockfile entries that do not resolve from registry.npmjs.org', () => {
    const findings = checkLockfileIntegrity({
      packages: {
        '': { resolved: 'https://registry.npmjs.org/root/-/root-1.tgz' },
        'node_modules/evil': { resolved: 'https://evil.example/evil-1.0.0.tgz' },
        'node_modules/ok': { resolved: 'https://registry.npmjs.org/ok/-/ok-1.0.0.tgz' },
      },
    });
    expect(findings.some((f) => f.ruleId === 'SUPPLY-LOCKURL-001' && f.message.includes('evil'))).toBe(
      true,
    );
    expect(findings.some((f) => f.message.includes('ok'))).toBe(false);
  });

  it('flags private-scope names that also exist on the public registry', () => {
    const hit = checkDependencyConfusion('@acme/internal', '@acme:registry=https://npm.acme.example/', true);
    expect(hit.some((f) => f.ruleId === 'SUPPLY-CONFUSION-001')).toBe(true);
    const miss = checkDependencyConfusion('@acme/internal', '@acme:registry=https://npm.acme.example/', false);
    expect(miss).toEqual([]);
  });

  it('flags a package that dropped npm provenance', () => {
    expect(checkProvenance(true, false).some((f) => f.ruleId === 'SUPPLY-PROVENANCE-001')).toBe(true);
    expect(checkProvenance(true, true)).toEqual([]);
    expect(checkProvenance(false, false)).toEqual([]);
  });
});
