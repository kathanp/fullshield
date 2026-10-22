import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, oauthFindings, type OAuthMachine } from '../../../src/phases/p318.js';

function machine(over: Partial<OAuthMachine> = {}): OAuthMachine {
  return {
    file: 'oauth.js',
    line: 8,
    library: 'passport',
    modelRow: false,
    publicClient: false,
    wroteState: true,
    comparedState: true,
    stateDominatesToken: true,
    pkce: false,
    redirectFrom: 'literal',
    acceptsIdToken: false,
    nonceCompared: false,
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 318 oauth', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(oauthFindings([machine({ wroteState: false })])).toEqual([]);
  });

  it('reports each missing edge on its own and nothing for a complete flow', () => {
    process.env[FLAG] = '1';
    expect(oauthFindings([machine({ wroteState: false })]).map((row) => row.edge)).toEqual(['state']);
    expect(oauthFindings([machine({ publicClient: true, pkce: false })]).map((row) => row.edge)).toEqual(['pkce']);
    expect(oauthFindings([machine({ redirectFrom: 'request' })]).map((row) => row.edge)).toEqual(['redirect_uri']);
    expect(oauthFindings([machine({ acceptsIdToken: true, nonceCompared: false })]).map((row) => row.edge)).toEqual(['nonce']);
    expect(oauthFindings([machine({ publicClient: true, pkce: true, acceptsIdToken: true, nonceCompared: true })])).toEqual([]);
  });

  it('does not report PKCE for a confidential client and ignores a literal redirect', () => {
    process.env[FLAG] = '1';
    expect(oauthFindings([machine({ publicClient: false, pkce: false })])).toEqual([]);
    expect(oauthFindings([machine({ redirectFrom: 'literal' })])).toEqual([]);
  });

  it('counts a dominating helper and ignores a helper that is never called', () => {
    process.env[FLAG] = '1';
    expect(oauthFindings([machine({ comparedState: true, stateDominatesToken: true })])).toEqual([]);
    expect(oauthFindings([machine({ comparedState: false, stateDominatesToken: false })]).map((row) => row.edge)).toEqual(['state']);
  });
});
