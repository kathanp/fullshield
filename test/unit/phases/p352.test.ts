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
});
