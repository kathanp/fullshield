import { afterEach, describe, expect, it } from 'vitest';

import { corsFindings, enabled, FLAG } from '../../../src/phases/p323.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 323 cors', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(corsFindings({ file: 'a.js', line: 1, origin: { kind: 'reflect-request' }, credentials: true }).findings).toEqual([]);
  });

  it('emits nothing for a literal origin and reports reflect with credentials', () => {
    process.env[FLAG] = '1';
    expect(corsFindings({ file: 'a.js', line: 1, origin: { kind: 'literal', value: 'https://app.example' }, credentials: true }).findings).toEqual([]);
    expect(corsFindings({ file: 'a.js', line: 2, origin: { kind: 'reflect-request' }, credentials: true }).findings[0]?.severity).toBe('critical');
  });

  it('puts the suffix counterexample in the witness and accepts an anchored host', () => {
    process.env[FLAG] = '1';
    const suffix = corsFindings({ file: 'a.js', line: 3, origin: { kind: 'regex', source: 'evil\\.com$' }, credentials: false });
    expect(suffix.findings[0]?.witness).toContain('notevil.com');
    expect(corsFindings({ file: 'a.js', line: 4, origin: { kind: 'regex', source: '^evil\\.com$' }, credentials: false }).findings).toEqual([]);
  });

  it('reports a null origin and does not call the unknown regex safe', () => {
    process.env[FLAG] = '1';
    expect(corsFindings({ file: 'a.js', line: 5, origin: { kind: 'literal', value: 'null' }, credentials: false }).findings[0]?.severity).toBe('high');
    const unknown = corsFindings({ file: 'a.js', line: 6, origin: { kind: 'regex', source: '(evil)\\1' }, credentials: false });
    expect(unknown.findings[0]?.message.toLowerCase()).not.toContain('safe');
  });
});
