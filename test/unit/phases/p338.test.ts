import { afterEach, describe, expect, it } from 'vitest';

import { ciFindings, enabled, FLAG } from '../../../src/phases/p338.js';
import type { SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const formats: SecretFormat[] = [{
  id: 'synth', source: 'https://example.invalid/grammar', prefix: 'fsyn_', alphabet: 'A-Za-z0-9', length: 16, notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
}];

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 338 ci secrets', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(ciFindings('.github/workflows/ci.yml', `TOKEN: ${TOKEN}`, formats)).toEqual([]);
  });

  it('reports a literal env value and ignores a secrets expression', () => {
    process.env[FLAG] = '1';
    expect(ciFindings('.github/workflows/ci.yml', `env:\n  TOKEN: ${TOKEN}\n`, formats)[0]?.severity).toBe('high');
    expect(ciFindings('.github/workflows/ci.yml', 'env:\n  TOKEN: ${{ secrets.TOKEN }}\n', formats)).toEqual([]);
  });

  it('reports a literal beside an expression and rates an echo as info', () => {
    process.env[FLAG] = '1';
    const beside = `TOKEN: \${{ secrets.TOKEN }}\nOTHER: ${TOKEN}\n`;
    expect(ciFindings('.github/workflows/ci.yml', beside, formats).some((row) => row.severity === 'high')).toBe(true);
    expect(ciFindings('.github/workflows/ci.yml', 'run: echo ${{ secrets.TOKEN }}', formats)[0]?.severity).toBe('info');
  });
});
