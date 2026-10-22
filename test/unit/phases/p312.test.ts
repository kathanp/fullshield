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
});
