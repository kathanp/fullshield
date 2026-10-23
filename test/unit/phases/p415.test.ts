import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, jwtOpt } from '../../../src/phases/p415.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 415', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(jwtOpt('pem').source).toBe('jwt.verify(token, key)');
  });

  it('writes one algorithm family and refuses a mixed key', () => {
    process.env[FLAG] = '1';
    expect(jwtOpt('pem').source).toContain("['RS256']");
    expect(jwtOpt('hmac').source).toContain("['HS256']");
    const mixed = jwtOpt('mixed');
    expect(mixed.refused).toBe(true);
    expect(mixed.source).toBe('jwt.verify(token, key)');
    expect(jwtOpt('pem').source.includes('none')).toBe(false);
    expect(jwtOpt('pss').refused).toBe(true);
  });
});
