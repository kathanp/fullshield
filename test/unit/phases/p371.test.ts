import { describe, expect, it } from 'vitest';

import { enabled, FLAG, FLOAT_FLAG, pinPolicyFindings } from '../../../src/phases/p371.js';
import { FsError, loadSupplyPolicy, POLICY_FLAG } from '../../../src/phases/p378.js';

describe('phase 371 pin policy', () => {
  it('emits nothing without a policy', () => {
    process.env[FLAG] = '1';
    expect(pinPolicyFindings([{ name: 'left-pad', spec: '^1.0.0' }], null)).toEqual([]);
  });

  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(
      pinPolicyFindings([{ name: 'left-pad', spec: '^1.0.0' }], {
        allowedRegistries: [],
        allowedScriptCapabilities: [],
        pinMode: 'exact',
        secretAllow: [],
        privateRegistryHosts: [],
        pinSeverity: null,
      }),
    ).toEqual([]);
  });

  it('reports a range when policy says exact', () => {
    process.env[FLAG] = '1';
    const findings = pinPolicyFindings([{ name: 'left-pad', spec: '^1.0.0' }], {
      allowedRegistries: [],
      allowedScriptCapabilities: [],
      pinMode: 'exact',
      secretAllow: [],
      privateRegistryHosts: [],
      pinSeverity: 'low',
    });
    expect(findings.map((row) => row.ruleId)).toEqual(['DEPS-PIN-POLICY-001']);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.message).toContain('policy');
  });

  it('emits nothing for an exact version and for workspace:*', () => {
    process.env[FLAG] = '1';
    const policy = {
      allowedRegistries: [],
      allowedScriptCapabilities: [],
      pinMode: 'exact' as const,
      secretAllow: [],
      privateRegistryHosts: [],
      pinSeverity: null,
    };
    expect(pinPolicyFindings([{ name: 'left-pad', spec: '1.2.3' }], policy)).toEqual([]);
    expect(pinPolicyFindings([{ name: 'pkg', spec: 'workspace:*' }], policy)).toEqual([]);
  });

  it('emits both ids when a range violates 128 and this policy, with different messages', () => {
    process.env[FLAG] = '1';
    process.env[FLOAT_FLAG] = '1';
    const findings = pinPolicyFindings([{ name: 'left-pad', spec: '*' }], {
      allowedRegistries: [],
      allowedScriptCapabilities: [],
      pinMode: 'exact',
      secretAllow: [],
      privateRegistryHosts: [],
      pinSeverity: null,
    });
    expect(findings.map((row) => row.ruleId)).toEqual(['DEPS-PIN-POLICY-001', 'DEPS-FLOAT-001']);
    expect(findings[0]?.message).not.toBe(findings[1]?.message);
  });

  it('fails to load a policy severity of critical', () => {
    process.env[POLICY_FLAG] = '1';
    expect(() => loadSupplyPolicy('{"pinMode":"exact","pinSeverity":"critical"}')).toThrow(FsError);
  });

  it('emits the lower float id for an open range and skips a bounded range', () => {
    process.env[FLAG] = '1';
    process.env[FLOAT_FLAG] = '1';
    const policy = {
      allowedRegistries: [],
      allowedScriptCapabilities: [],
      pinMode: 'exact' as const,
      secretAllow: [],
      privateRegistryHosts: [],
      pinSeverity: null,
    };
    const open = pinPolicyFindings(
      [
        { name: 'a', spec: '>=1.0.0' },
        { name: 'b', spec: '>1.0.0' },
        { name: 'c', spec: 'x' },
        { name: 'd', spec: 'X' },
        { name: 'e', spec: 'latest' },
        { name: 'f', spec: '' },
        { name: 'g', spec: '^1.2.3' },
        { name: 'h', spec: '>=1.0.0 <2.0.0' },
        { name: 'i', spec: '1.2.3-beta.1' },
        { name: 'j', spec: '1.2.3+build.1' },
      ],
      policy,
    );
    expect(open.filter((row) => row.ruleId === 'DEPS-FLOAT-002').map((row) => row.name)).toEqual(['a', 'b']);
    expect(open.filter((row) => row.ruleId === 'DEPS-FLOAT-001').map((row) => row.name)).toEqual(['c', 'd', 'e', 'f']);
    expect(open.filter((row) => row.name === 'g').map((row) => row.ruleId)).toEqual(['DEPS-PIN-POLICY-001']);
    expect(open.filter((row) => row.name === 'h').map((row) => row.ruleId)).toEqual(['DEPS-PIN-POLICY-001']);
    expect(open.filter((row) => row.name === 'i' || row.name === 'j')).toEqual([]);
    expect(pinPolicyFindings([{ name: 'left-pad', spec: '^1.0.0' }], { ...policy, pinMode: 'range' })).toEqual([]);
    delete process.env[FLAG];
    delete process.env[FLOAT_FLAG];
  });
});
