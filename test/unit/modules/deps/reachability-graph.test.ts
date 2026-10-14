import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';

const reachabilityApp = join(process.cwd(), 'test', 'fixtures', 'reachability-app');
const devdepApp = join(process.cwd(), 'test', 'fixtures', 'devdep-app');
const devdepImported = join(process.cwd(), 'test', 'fixtures', 'devdep-imported-app');

describe('transitive reachability (harden-3)', () => {
  it('keeps severity for a transitive of an imported+called direct dependency and records the path', async () => {
    const result = await scan({ cwd: reachabilityApp, modules: ['deps'] });
    const minimist = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('minimist@'),
    );
    expect(minimist.length).toBeGreaterThan(0);
    expect(minimist.every((f) => f.reachability === 'reachable-via-dependency')).toBe(true);
    expect(minimist.every((f) => f.severity === 'medium')).toBe(true);
    const path = minimist[0]?.dependencyPath ?? [];
    expect(path[0]).toBe('express');
    expect(path[path.length - 1]).toBe('minimist');
    expect(path.join(' > ')).toMatch(/express > .+minimist/);
    expect(minimist[0]?.message).toContain('express >');
    expect(minimist[0]?.message).toContain('minimist');
  });

  it('uses not-imported (−2) only when no lockfile path reaches an imported direct dependency', async () => {
    const result = await scan({ cwd: reachabilityApp, modules: ['deps'] });
    const lodash = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('lodash@'),
    );
    expect(lodash.length).toBeGreaterThan(0);
    expect(lodash.every((f) => f.reachability === 'not-imported')).toBe(true);
    // critical − 2 = medium; must not stay critical/high
    expect(lodash.every((f) => f.severity === 'medium')).toBe(true);
    expect(lodash.every((f) => !/\bdev-only\b/.test(f.message))).toBe(true);
  });
});

describe('devDependency vulnerabilities (harden-3)', () => {
  it('downgrades unused-by-production devDependencies to info with a dev-only note', async () => {
    const result = await scan({ cwd: devdepApp, modules: ['deps'] });
    const lodash = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('lodash@'),
    );
    expect(lodash.length).toBeGreaterThan(0);
    expect(lodash.every((f) => f.severity === 'info')).toBe(true);
    expect(lodash.every((f) => /\bdev-only\b/.test(f.message))).toBe(true);
  });

  it('keeps severity when production source imports a package listed as a devDependency', async () => {
    const result = await scan({ cwd: devdepImported, modules: ['deps'] });
    const lodash = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('lodash@'),
    );
    expect(lodash.length).toBeGreaterThan(0);
    expect(lodash.every((f) => f.reachability === 'reachable')).toBe(true);
    expect(lodash.some((f) => f.severity === 'critical')).toBe(true);
    expect(lodash.every((f) => !/\bdev-only\b/.test(f.message))).toBe(true);
  });
});
