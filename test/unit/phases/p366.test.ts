import { describe, expect, it } from 'vitest';

import { enabled, FLAG, POLICY_FLAG, publicScopeFindings } from '../../../src/phases/p366.js';

const base = {
  rootPrivate: true,
  rootName: '@root/app',
  dependencyName: '@root/pkg',
  resolved: 'https://registry.npmjs.org/@root/pkg/-/pkg-1.0.0.tgz',
  policyPrivateHosts: null,
};

describe('phase 366 public scope', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(publicScopeFindings(base)).toEqual([]);
  });

  it('reports a private root depending on a scope resolved at the public registry', () => {
    process.env[FLAG] = '1';
    const findings = publicScopeFindings(base);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('DEPS-PUBLIC-SCOPE-001');
    expect(findings[0]?.message).toContain('public registry');
    expect(findings[0]?.message).toContain('privateRegistryHosts');
    expect(findings[0]?.message.toLowerCase()).not.toContain('should not exist');
  });

  it('does not report a link: workspace copy', () => {
    process.env[FLAG] = '1';
    expect(publicScopeFindings({ ...base, resolved: 'link:./packages/pkg' })).toEqual([]);
  });

  it('does not report a policy host match', () => {
    process.env[FLAG] = '1';
    process.env[POLICY_FLAG] = '1';
    expect(
      publicScopeFindings({
        ...base,
        policyPrivateHosts: ['registry.npmjs.org'],
      }),
    ).toEqual([]);
  });
});
