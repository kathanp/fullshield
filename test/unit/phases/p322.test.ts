import { afterEach, describe, expect, it } from 'vitest';

import { csrfFindings, enabled, FLAG, type CsrfRoute } from '../../../src/phases/p322.js';

function route(over: Partial<CsrfRoute> = {}): CsrfRoute {
  return {
    file: 'app.js',
    line: 4,
    method: 'POST',
    path: '/account',
    authKind: 'session',
    catalogCsrf: false,
    tokenCompare: false,
    headerDominates: false,
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 322 csrf', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(csrfFindings([route()])).toEqual([]);
  });

  it('reports a cookie session POST without a check and keeps SameSite in the witness', () => {
    process.env[FLAG] = '1';
    const findings = csrfFindings([route({ sameSite: 'lax' })]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.witness).toContain('lax');
  });

  it('does not report dominating middleware, bearer auth, or GET', () => {
    process.env[FLAG] = '1';
    expect(csrfFindings([route({ catalogCsrf: true })])).toEqual([]);
    expect(csrfFindings([route({ authKind: 'jwt' })])).toEqual([]);
    expect(csrfFindings([route({ method: 'GET' })])).toEqual([]);
  });

  it('records an absent SameSite and a header that is outside the catalog', () => {
    process.env[FLAG] = '1';
    const absent = csrfFindings([route()]);
    expect(absent[0]?.witness).toBe('sameSite=absent');
    expect(csrfFindings([route({ method: 'post' })]).length).toBe(1);
    expect(csrfFindings([route({ authKind: 'passport:local' })]).length).toBe(1);
    expect(csrfFindings([route({ authKind: 'passport:local', passportSession: false })])).toEqual([]);
    expect(csrfFindings([route({ tokenCompare: true })])).toEqual([]);
    expect(csrfFindings([route({ customHeader: 'x-csrf', headerDominates: true })])).toEqual([]);
    expect(csrfFindings([route({ customHeader: 'x-csrf', headerDominates: true })], { headerNames: ['x-csrf'] })).toEqual([]);
    const unknown = csrfFindings([route({ customHeader: 'x-other' })], { headerNames: ['x-csrf'] });
    expect(unknown[0]?.message).toContain('not in the catalog');
    expect(csrfFindings([route({ method: 'PURGE' })]).length).toBe(0);
    expect(csrfFindings([route({ method: 'PURGE' })], { methods: ['purge'] }).length).toBe(1);
  });
});
