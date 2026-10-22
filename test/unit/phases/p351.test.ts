import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p351.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 351', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.reproFindings([{ name: 'left', range: '^1.0.0', locked: '1.0.0', versions: ['1.2.0'], direct: true }]).findings).toEqual([]);
  });

  it('reports a lock that is not the highest match and skips an indirect dep', () => {
    process.env[phase.FLAG] = '1';
    const hit = phase.reproFindings([{ name: 'left', range: '^1.0.0', locked: '1.0.0', versions: ['1.0.0', '1.2.0'], direct: true }]);
    expect(hit.findings[0]?.ruleId).toBe(phase.RULE);
    expect(phase.reproFindings([{ name: 'left', range: '^1.0.0', locked: '1.0.0', versions: ['1.2.0'], direct: false }]).findings).toEqual([]);
  });
});
