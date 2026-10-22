import { describe, expect, it } from 'vitest';

import { enabled, FLAG, TYPEONLY_FLAG, unusedSymbols } from '../../../src/phases/p376.js';

describe('phase 376 unused symbols', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(unusedSymbols("import { a } from 'pkg';\n", ['pkg'])).toEqual([]);
  });

  it('reports an unused named import', () => {
    process.env[FLAG] = '1';
    const findings = unusedSymbols("import { a } from 'pkg';\nexport const n = 1;\n", ['pkg']);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('info');
    expect(findings[0]?.names).toEqual(['a']);
  });

  it('does not report a side-effect import', () => {
    process.env[FLAG] = '1';
    expect(unusedSymbols("import 'pkg';\n", ['pkg'])).toEqual([]);
  });

  it('does not count a type-only import as use when phase 240 is on', () => {
    process.env[FLAG] = '1';
    process.env[TYPEONLY_FLAG] = '1';
    const findings = unusedSymbols("import type { T } from 'pkg';\nexport const n = 1;\n", ['pkg']);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('Type-only');
  });

  it('counts a type-only import as use when phase 240 is off', () => {
    process.env[FLAG] = '1';
    expect(unusedSymbols("import type { T } from 'pkg';\nexport const n = 1;\n", ['pkg'])).toEqual([]);
  });

  it('emits nothing for a dynamic import(name)', () => {
    process.env[FLAG] = '1';
    expect(unusedSymbols('export async function load(name) { return import(name); }\n', ['pkg'])).toEqual([]);
  });
});
