import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, sessionFindings, type SessionCookie } from '../../../src/phases/p319.js';

function cookie(over: Partial<SessionCookie> = {}): SessionCookie {
  return {
    file: 'session.js',
    line: 2,
    name: 'sid',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    secret: { kind: 'env', name: 'SESSION_SECRET' },
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 319 session configuration', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(sessionFindings([cookie({ httpOnly: undefined })])).toEqual([]);
  });

  it('emits nothing for httpOnly, sameSite lax, and a long env secret', () => {
    process.env[FLAG] = '1';
    expect(sessionFindings([cookie()])).toEqual([]);
  });

  it('reports a missing httpOnly, a 4-character secret, and saveUninitialized', () => {
    process.env[FLAG] = '1';
    expect(sessionFindings([cookie({ httpOnly: undefined })]).some((row) => row.ruleId === 'CONFIG-SESSION-HTTPONLY-001')).toBe(true);
    const secret = 'abcd';
    const short = sessionFindings([cookie({ secret: { kind: 'literal', value: secret } })]);
    expect(short.some((row) => row.ruleId === 'CONFIG-SESSION-SECRET-001')).toBe(true);
    expect(JSON.stringify(short)).not.toContain(secret);
    expect(sessionFindings([cookie({ saveUninitialized: true })]).some((row) => row.severity === 'info')).toBe(true);
  });

  it('does not treat a token cookie as a csrf exception', () => {
    process.env[FLAG] = '1';
    expect(sessionFindings([cookie({ name: 'csrf', httpOnly: false })]).some((row) => row.ruleId === 'CONFIG-SESSION-HTTPONLY-001')).toBe(false);
    expect(sessionFindings([cookie({ name: 'token', httpOnly: false })]).some((row) => row.ruleId === 'CONFIG-SESSION-HTTPONLY-001')).toBe(true);
  });
});
