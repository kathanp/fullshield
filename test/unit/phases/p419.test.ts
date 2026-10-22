import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, protoKey } from '../../../src/phases/p419.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 419', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(protoKey({ tainted: true, callsMethod: false, constantKey: false, freeFormMap: false }).edit).toBeNull();
  });

  it('guards a method call and uses a null prototype only for pure assignment', () => {
    process.env[FLAG] = '1';
    const method = protoKey({ tainted: true, callsMethod: true, constantKey: false, freeFormMap: false });
    expect(method.edit).toContain('__proto__');
    expect(method.edit?.includes('Object.create(null)')).toBe(false);
    expect(protoKey({ tainted: true, callsMethod: false, constantKey: false, freeFormMap: false }).edit).toBe('Object.create(null)');
    expect(protoKey({ tainted: true, callsMethod: false, constantKey: true, freeFormMap: false }).edit).toBeNull();
    expect(protoKey({ tainted: true, callsMethod: false, constantKey: false, freeFormMap: true }).disposition).toBe('review');
  });
});
