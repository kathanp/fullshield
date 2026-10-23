import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, gqlAuthzFindings, type GqlField } from '../../../src/phases/p327.js';

function field(over: Partial<GqlField> = {}): GqlField {
  return {
    file: 'schema.js',
    line: 3,
    parent: 'User',
    field: 'email',
    parentPublic: true,
    directiveCatalog: false,
    reachesStore: false,
    sensitive: true,
    returnsLiteral: false,
    introspection: false,
    queryCheckDominates: false,
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 327 graphql authz', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(gqlAuthzFindings([field()])).toEqual([]);
  });

  it('reports a public sensitive field and accepts @auth and a literal', () => {
    process.env[FLAG] = '1';
    const open = gqlAuthzFindings([field()]);
    expect(open[0]?.ruleId).toBe('SAST-GQL-AUTHZ-001');
    expect(gqlAuthzFindings([field({ directive: '@auth', directiveCatalog: true })])).toEqual([]);
    expect(gqlAuthzFindings([field({ returnsLiteral: true, sensitive: false })])).toEqual([]);
  });

  it('still reports when middleware does not dominate, and quotes an unknown directive', () => {
    process.env[FLAG] = '1';
    const findings = gqlAuthzFindings([field({ directive: '@custom', directiveCatalog: false, queryCheckDominates: false })]);
    expect(findings[0]?.witness).toBe('@custom');
  });
});
