import { afterEach, describe, expect, it } from 'vitest';

import { annotateSinks, enabled, FLAG, type SinkCheck } from '../../../src/phases/p312.js';

function sink(checks: SinkCheck['checks']): SinkCheck {
  return { id: 's', sinkClass: 'db', sinkOrder: 5, checks };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 312 authorization', () => {
  it('returns the same sinks when the flag is off', () => {
    const sinks = [sink([{ name: 'hasRole', order: 1, shape: 'return-or-throw', catalog: true, computed: false }])];
    expect(enabled()).toBe(false);
    expect(annotateSinks(sinks)).toBe(sinks);
  });

  it('sets the predicate when the catalog check dominates the sink', () => {
    process.env[FLAG] = '1';
    const out = annotateSinks([sink([{ name: 'hasRole', order: 1, shape: 'return-or-throw', catalog: true, computed: false }])]);
    const first = out[0];
    expect(first && 'authz' in first ? first.authz.kind : '').toBe('role');
  });

  it('ignores the same check after the sink', () => {
    process.env[FLAG] = '1';
    const out = annotateSinks([sink([{ name: 'hasRole', order: 9, shape: 'return-or-throw', catalog: true, computed: false }])]);
    const first = out[0];
    expect(first && 'authz' in first ? first.authz.kind : '').toBe('none');
  });

  it('accepts a config-named function', () => {
    process.env[FLAG] = '1';
    const out = annotateSinks([sink([{ name: 'allow', order: 1, shape: 'return-or-throw', catalog: false, computed: false }])], {
      names: { allow: 'role' },
    });
    const first = out[0];
    expect(first && 'authz' in first ? first.authz.kind : '').toBe('role');
  });

  it('leaves an unlisted can helper as none', () => {
    process.env[FLAG] = '1';
    const out = annotateSinks([sink([{ name: 'can', order: 1, shape: 'return-or-throw', catalog: false, computed: false }])]);
    const first = out[0];
    expect(first && 'authz' in first ? first.authz.kind : '').toBe('none');
  });

  it('recognizes permission, policy, and ownership checks and a computed name', () => {
    process.env[FLAG] = '1';
    const names = ['can', 'CASL', 'Ability', 'authorize', 'casbin', 'enforcer', 'isOwner', 'ownership'] as const;
    for (const name of names) {
      const out = annotateSinks([sink([{ name, order: 1, shape: 'return-or-throw', catalog: true, computed: false }])]);
      const first = out[0];
      expect(first && 'authz' in first ? first.authz.kind : '').not.toBe('none');
    }
    const computed = annotateSinks([sink([{ name: 'hasRole', order: 1, shape: 'return-or-throw', catalog: true, computed: true }])]);
    expect(computed[0] && 'authz' in computed[0] ? computed[0].authz : undefined).toMatchObject({ kind: 'unknown', check: 'hasRole' });
    const other = annotateSinks([sink([{ name: 'hasRole', order: 1, shape: 'other', catalog: true, computed: false }])]);
    expect(other[0] && 'authz' in other[0] ? other[0].authz.kind : '').toBe('none');
    const same = annotateSinks([sink([{ name: 'hasRole', order: 5, shape: 'return-or-throw', catalog: true, computed: false }])]);
    expect(same[0] && 'authz' in same[0] ? same[0].authz.kind : '').toBe('none');
    const missing = annotateSinks([sink([{ name: 'custom', order: 1, shape: 'return-or-throw', catalog: true, computed: false }])]);
    expect(missing[0] && 'authz' in missing[0] ? missing[0].authz.kind : '').toBe('none');
  });
});
