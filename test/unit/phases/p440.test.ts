import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, splitReports, type MonoFinding, type WorkspacePackage } from '../../../src/phases/p440.js';

afterEach(() => {
  delete process.env[FLAG];
});

const packages: WorkspacePackage[] = [
  { name: 'app', dir: 'packages/app', dependencies: ['lib'] },
  { name: 'web', dir: 'packages/app/web', dependencies: [] },
  { name: 'lib', dir: 'packages/lib', dependencies: [] },
  { name: 'empty', dir: 'packages/empty', dependencies: [] },
];

const findings: MonoFinding[] = [
  { fingerprint: 'fp-web', file: 'packages/app/web/index.js', ruleId: 'R', line: 1, severity: 'high' },
  { fingerprint: 'fp-app', file: 'packages/app/website.js', ruleId: 'R', line: 2, severity: 'high' },
  { fingerprint: 'fp-lib', file: 'packages/lib/src/a.js', ruleId: 'R', line: 3, severity: 'medium' },
  { fingerprint: 'fp-root', file: 'README.md', ruleId: 'R', line: 1, severity: 'low' },
];

describe('phase 440 monorepo reports', () => {
  it('returns the single report when the flag is off', () => {
    expect(enabled()).toBe(false);
    const baseline = 'one-report';
    const result = splitReports(baseline, findings, packages);
    expect(result).toEqual({ single: baseline, packages: {}, rollupCount: 0 });
    expect(result.single).toBe(baseline);
  });

  it('splits findings by the longest package directory', () => {
    process.env[FLAG] = '1';
    const result = splitReports('one-report', findings, packages);
    expect(result.single).toBeNull();
    expect(result.rollupCount).toBe(4);
    expect(result.packages.web?.findings.map((row) => row.path)).toEqual(['index.js']);
    expect(result.packages.app?.findings.map((row) => row.path)).toEqual(['website.js']);
    expect(result.packages.lib?.findings.map((row) => row.path)).toEqual(['src/a.js']);
    expect(result.packages._root?.findings.map((row) => row.path)).toEqual(['README.md']);
    expect(result.packages.app?.inherited).toEqual(['lib']);
    expect(result.packages).not.toHaveProperty('empty');
  });

  it('counts a repeated fingerprint once and does not inherit an empty package', () => {
    process.env[FLAG] = '1';
    const repeated: MonoFinding[] = [
      { fingerprint: 'fp-lib', file: 'packages/lib/src/a.js', ruleId: 'R', line: 3, severity: 'medium' },
      { fingerprint: 'fp-lib', file: 'packages/lib/src/b.js', ruleId: 'R', line: 4, severity: 'medium' },
    ];
    const result = splitReports('one-report', repeated, packages);
    expect(result.rollupCount).toBe(1);
    expect(result.packages.app?.inherited).toEqual(['lib']);
    expect(result.packages.lib?.findings).toHaveLength(2);
    expect(result.packages).not.toHaveProperty('empty');
    expect(result.packages).not.toHaveProperty('web');
  });
});
