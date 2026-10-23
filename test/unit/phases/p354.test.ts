import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p354.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 354', () => {
  it('returns the original text when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.foldSource('String.fromCharCode(99, 117, 114, 108)').text).toContain('fromCharCode');
  });

  it('folds a char-code literal and stops at eval', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.foldSource('String.fromCharCode(99, 117, 114, 108)').text).toContain('curl');
    expect(phase.foldSource('eval(payload)').events).toContain('fold stopped at eval');
  });

  it('leaves a non-numeric char code, folds hex and base64, and stops at Function', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.foldSource('String.fromCharCode(99, x)').text).toContain('fromCharCode');
    expect(phase.foldSource("'\\x63\\x75' + '\\x72\\x6c'").text).toContain('curl');
    expect(phase.foldSource("Buffer.from('Y3VybA==', 'base64')").text).toContain('curl');
    expect(phase.foldSource("Buffer.from('6375726c', 'hex')").text).toContain('curl');
    const payload = 'a'.repeat(300);
    const long = phase.foldSource(`Buffer.from('${Buffer.from(payload).toString('base64')}', 'base64')`);
    expect(long.partial).toBe(true);
    expect(long.events).toContain('fold was partial');
    expect(long.text).toContain(`'${'a'.repeat(256)}'`);
    const hex = '61'.repeat(300);
    expect(phase.foldSource(`Buffer.from('${hex}', 'hex')`).partial).toBe(true);
    expect(phase.foldSource('Function(payload)').events).toContain('fold stopped at eval');
  });
});
