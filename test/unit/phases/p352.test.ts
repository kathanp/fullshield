import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p352.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 352', () => {
  it('refuses when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(() => phase.dependencyFlags(() => '', new Map())).toThrow(phase.DepFlagsError);
  });

  it('flags a new direct dependency and rejects a score field', () => {
    process.env[phase.FLAG] = '1';
    const rows = phase.dependencyFlags(() => '+  "left": "1.0.0"', new Map([['left', { installScript: true }]]));
    expect(rows[0]?.riskFlags).toContain('new-direct');
    expect(rows[0]?.riskFlags).toContain('install-script');
    expect(() => phase.assertNoScore({ score: 1 })).toThrow(/score/);
  });

  it('ignores context lines, an unchanged pin, and a bump with no risk token', () => {
    process.env[phase.FLAG] = '1';
    const diff = [
      '--- a/package.json',
      '+++ b/package.json',
      'not a dependency line',
      '-  "same": "1.0.0"',
      '+  "same": "1.0.0"',
      '-  "bumped": "1.0.0"',
      '+  "bumped": "1.0.1"',
      '+  "fresh": "2.0.0"',
    ].join('\n');
    const facts = new Map<string, phase.DepFacts>([
      ['fresh', { advisoryCritical: true, resolvedHost: 'npm.example.invalid', installScript: false }],
      ['reg', { resolvedHost: 'registry.npmjs.org' }],
    ]);
    const rows = phase.dependencyFlags(() => diff, facts);
    expect(rows.map((row) => row.name)).toEqual(['fresh']);
    expect(rows[0]?.riskFlags).toEqual(['advisory-critical', 'new-direct', 'non-registry-host']);
    expect(phase.dependencyFlags(() => '+  "reg": "1.0.0"', facts).map((row) => row.riskFlags)).toEqual([['new-direct']]);
    expect(phase.assertNoScore(null)).toBeUndefined();
  });
});
