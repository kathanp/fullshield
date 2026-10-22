import { afterEach, describe, expect, it } from 'vitest';

import { cookieFlags, enabled, FLAG } from '../../../src/phases/p416.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 416', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(cookieFlags({ options: '{}', name: 'sid', env: 'absent' }).source).toBe('{}');
  });

  it('adds missing flags and leaves explicit choices', () => {
    process.env[FLAG] = '1';
    const added = cookieFlags({ options: '{}', name: 'sid', env: 'production' });
    expect(added.source).toContain('httpOnly: true');
    expect(added.source).toContain("sameSite: 'lax'");
    expect(added.disposition).toBe('safe');
    const none = cookieFlags({ options: "{ sameSite: 'none', secure: true }", name: 'sid', env: 'production' });
    expect(none.reported).toBe(true);
    expect(none.source).toContain("sameSite: 'none'");
    const csrf = cookieFlags({ options: '{ httpOnly: false }', name: 'csrf', env: 'production' });
    expect(csrf.source).toBe('{ httpOnly: false }');
    const present = "{ httpOnly: true, secure: true, sameSite: 'lax' }";
    expect(cookieFlags({ options: present, name: 'sid', env: 'production' }).source).toBe(present);
    expect(cookieFlags({ options: '{}', name: 'sid', env: 'development' }).disposition).toBe('review');
  });
});
