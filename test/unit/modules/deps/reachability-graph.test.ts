import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import {
  classifyReachability,
  reachabilitySteps,
} from '../../../../src/modules/deps/reachability.js';

const reachabilityApp = join(process.cwd(), 'test', 'fixtures', 'reachability-app');
const yarnApp = join(process.cwd(), 'test', 'fixtures', 'yarn-reachability-app');
const pnpmApp = join(process.cwd(), 'test', 'fixtures', 'pnpm-reachability-app');
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

  it('keeps severity as reachability-unknown when the lockfile has no parsed edges', () => {
    const graph = {
      packages: [],
      edges: new Map<string, Set<string>>(),
      directProd: new Set(['express']),
      directDev: new Set<string>(),
      edgesKnown: false,
    };
    const usage = new Map([['express', { imported: true, called: true }]]);
    expect(classifyReachability('qs', usage, graph)).toEqual({ reachability: 'reachability-unknown' });
    expect(reachabilitySteps('reachability-unknown')).toBe(0);
  });
});

describe('yarn and pnpm lockfile reachability (harden-4)', () => {
  it('classifies yarn transitives via real lockfile edges', async () => {
    const result = await scan({ cwd: yarnApp, modules: ['deps'] });
    const minimist = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('minimist@'),
    );
    expect(minimist.length).toBeGreaterThan(0);
    expect(minimist.every((f) => f.reachability === 'reachable-via-dependency')).toBe(true);
    expect(minimist.every((f) => f.severity === 'medium')).toBe(true);
    expect(minimist[0]?.dependencyPath?.join(' > ')).toMatch(/express > .+minimist/);

    const lodash = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('lodash@'),
    );
    expect(lodash.every((f) => f.reachability === 'not-imported')).toBe(true);
    expect(lodash.every((f) => f.severity === 'medium')).toBe(true);
  });

  it('classifies pnpm transitives via real lockfile edges', async () => {
    const result = await scan({ cwd: pnpmApp, modules: ['deps'] });
    const minimist = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('minimist@'),
    );
    expect(minimist.length).toBeGreaterThan(0);
    expect(minimist.every((f) => f.reachability === 'reachable-via-dependency')).toBe(true);
    expect(minimist.every((f) => f.severity === 'medium')).toBe(true);
    expect(minimist[0]?.dependencyPath?.join(' > ')).toMatch(/express > .+minimist/);

    const lodash = result.findings.filter(
      (f) => f.ruleId === 'DEPS-VULN-001' && (f.snippet ?? '').startsWith('lodash@'),
    );
    expect(lodash.every((f) => f.reachability === 'not-imported')).toBe(true);
    expect(lodash.every((f) => f.severity === 'medium')).toBe(true);
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
