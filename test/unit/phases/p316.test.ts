import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, massFindings, RULE } from '../../../src/phases/p316.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 316 mass assignment', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(massFindings([{ file: 'a.js', line: 1, keys: 'unknown' }])).toEqual([]);
  });

  it('reports a whole-body update and an object spread as unknown keys', () => {
    process.env[FLAG] = '1';
    const findings = massFindings([{ file: 'a.js', line: 2, keys: 'unknown' }]);
    expect(findings[0]?.ruleId).toBe(RULE);
    expect(findings[0]?.witness).toBe('unknown keys');
    expect(findings[0]?.message).not.toContain('role');
  });

  it('reports a pick that keeps role and ignores a pick that drops it', () => {
    process.env[FLAG] = '1';
    const kept = massFindings([{ file: 'a.js', line: 3, keys: 'unknown', transfer: { kind: 'pick', keys: ['title', 'role'] } }]);
    const dropped = massFindings([{ file: 'a.js', line: 4, keys: 'unknown', transfer: { kind: 'pick', keys: ['title'] } }]);
    expect(kept[0]?.witness).toContain('role');
    expect(dropped).toEqual([]);
  });

  it('ignores a title-only write on a tagged model and a role field that is not tagged', () => {
    process.env[FLAG] = '1';
    const title = massFindings([
      { file: 'a.js', line: 5, keys: ['title'], model: { tags: { title: 'plain', role: 'plain' } } },
    ]);
    expect(title).toEqual([]);
    const byName = massFindings([{ file: 'a.js', line: 6, keys: ['role'] }]);
    expect(byName[0]?.message).toContain('by name');
  });
});
