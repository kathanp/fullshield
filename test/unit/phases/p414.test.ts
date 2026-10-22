import { afterEach, describe, expect, it } from 'vitest';

import { cryptoFix, enabled, FLAG, passwordEditIsSafe } from '../../../src/phases/p414.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 414', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(cryptoFix('password').edit).toBeNull();
  });

  it('replaces a password hash and a token, and leaves an allowed cache key', () => {
    process.env[FLAG] = '1';
    const password = cryptoFix('password');
    expect(password.edit).toContain('bcrypt');
    expect(passwordEditIsSafe(password.edit)).toBe(true);
    expect(passwordEditIsSafe("createHash('md5')")).toBe(false);
    expect(cryptoFix('token').edit).toContain('randomBytes');
    expect(cryptoFix('cache-allowed').edit).toBeNull();
    expect(cryptoFix('interop').disposition).toBe('review');
  });
});
