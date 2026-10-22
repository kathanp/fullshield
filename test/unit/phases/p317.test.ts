import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, jwtFindings, type JwtCall } from '../../../src/phases/p317.js';

function call(over: Partial<JwtCall> = {}): JwtCall {
  return {
    kind: 'verify',
    file: 'jwt.js',
    line: 3,
    algorithms: ['RS256'],
    key: 'pem-public',
    audience: false,
    issuer: false,
    issuerModel: 'local',
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 317 jwt edges', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(jwtFindings([call({ algorithms: ['HS256', 'RS256'] })])).toEqual([]);
  });

  it('reports HMAC plus RSA and does not report a single RS256 public PEM', () => {
    process.env[FLAG] = '1';
    expect(jwtFindings([call({ algorithms: ['HS256', 'RS256'], key: 'hmac' })]).map((row) => row.ruleId)).toContain('SAST-JWTDEEP-001');
    expect(jwtFindings([call()])).toEqual([]);
  });

  it('reports kid path and jku fetch with origin jwt-header', () => {
    process.env[FLAG] = '1';
    const path = jwtFindings([call({ kidFlowsTo: 'path' })]);
    const ssrf = jwtFindings([call({ headerUrlFlowsTo: 'fetch' })]);
    expect(path[0]?.ruleId).toBe('SAST-PATH-001');
    expect(path[0]?.origin).toBe('jwt-header');
    expect(ssrf[0]?.ruleId).toBe('SAST-SSRF-001');
  });

  it('does not report an issuer finding for a local HMAC verify and ignores the sign call', () => {
    process.env[FLAG] = '1';
    const local = jwtFindings([call({ algorithms: ['HS256'], key: 'hmac', audience: false, issuer: false, issuerModel: 'local' })]);
    const sign = jwtFindings([
      call({ kind: 'sign', algorithms: ['HS256', 'RS256'], key: 'hmac' }),
      call({ kind: 'verify', algorithms: ['RS256'], key: 'pem-public' }),
    ]);
    expect(local.map((row) => row.ruleId)).not.toContain('SAST-JWTDEEP-003');
    expect(sign).toEqual([]);
  });
});
