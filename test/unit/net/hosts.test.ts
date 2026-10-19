import { describe, expect, it } from 'vitest';

import { ALLOWED_HOSTS, isAllowlistedHost } from '../../../src/net/hosts.js';

describe('allowlisted hosts', () => {
  it('accepts OSV, the npm registry, and loopback', () => {
    expect(ALLOWED_HOSTS).toContain('api.osv.dev');
    expect(isAllowlistedHost('api.osv.dev')).toBe(true);
    expect(isAllowlistedHost('Registry.npmjs.org.')).toBe(true);
    expect(isAllowlistedHost('localhost')).toBe(true);
    expect(isAllowlistedHost('127.0.0.1')).toBe(true);
  });

  it('rejects a host that is not on the list', () => {
    expect(isAllowlistedHost('example.com')).toBe(false);
    expect(isAllowlistedHost('api.first.org')).toBe(false);
  });
});
