import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { enabled, FLAG, freezeBuiltins, prototypeFinding } from '../../../src/runtime/exp/p390.js';

describe('phase 390 prototype freeze', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(prototypeFinding('__proto__', true, true)).toBeNull();
  });

  it('reports a request key that can be __proto__', () => {
    process.env[FLAG] = '1';
    const finding = prototypeFinding('__proto__', true, true);
    expect(finding?.ruleId).toBe('SAST-PROTO-001');
    expect(finding?.message).toContain('opt-in');
  });

  it('freezes only when config asks, and import does not freeze builtins', () => {
    process.env[FLAG] = '1';
    expect(Object.isExtensible(Object.prototype)).toBe(true);
    const standin = { objectPrototype: {}, arrayPrototype: {}, functionPrototype: {} };
    freezeBuiltins(standin, false);
    expect(Object.isFrozen(standin.objectPrototype)).toBe(false);
    freezeBuiltins(standin, true);
    expect(Object.isFrozen(standin.objectPrototype)).toBe(true);
    const source = readFileSync(new URL('../../../src/runtime/exp/p390.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/^Object\.freeze/m);
    expect(Object.isExtensible(Object.prototype)).toBe(true);
  });
});
