import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, secretToEnv } from '../../../src/phases/p418.js';

const token = 'sk_live_example_token';
const other = 'sk_test_example_token';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 418', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(secretToEnv([token]).example).toBe('');
  });

  it('moves the literal to an env name and leaves the token out of the diff', () => {
    process.env[FLAG] = '1';
    const one = secretToEnv([token]);
    expect(one.source).toContain('process.env.');
    expect(one.source.includes(token)).toBe(false);
    expect(one.example.includes(token)).toBe(false);
    expect(one.diff.includes(token)).toBe(false);
    const two = secretToEnv([token, other]);
    const names = two.source.split('\n');
    expect(names[0]).not.toBe(names[1]);
  });
});
