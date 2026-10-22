import { afterEach, describe, expect, it } from 'vitest';

import { bruteFindings, enabled, FLAG, type SensitiveRoute } from '../../../src/phases/p321.js';

function route(over: Partial<SensitiveRoute> = {}): SensitiveRoute {
  return { file: 'auth.js', line: 1, path: '/login', kind: 'login', routeOrder: 10, ...over };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 321 brute force', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(bruteFindings([route()])).toEqual([]);
  });

  it('accepts a login route limited by username', () => {
    process.env[FLAG] = '1';
    expect(bruteFindings([route({ limiter: { order: 1, dominatesCredential: true, key: 'username' } })])).toEqual([]);
  });

  it('reports a limiter registered after the route and a constant key', () => {
    process.env[FLAG] = '1';
    const later = bruteFindings([route({ limiter: { order: 20, dominatesCredential: true, key: 'username' } })]);
    expect(later[0]?.witness).toBe('registered-after');
    const shared = bruteFindings([route({ limiter: { order: 1, dominatesCredential: true, key: 'constant' } })]);
    expect(shared[0]?.witness).toContain('bucket is shared');
  });

  it('does not report a health route', () => {
    process.env[FLAG] = '1';
    expect(bruteFindings([route({ path: '/health', kind: 'other' })])).toEqual([]);
    expect(bruteFindings([route({ path: '/author', kind: 'other' })])).toEqual([]);
  });
});
