import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { assertInsecureHosts, enabled, FLAG, FsError, homeNpmrcAllowed, PHASE_139_FLAG, readRegistrySources, registryFindings } from '../../../src/phases/p367.js';

describe('phase 367 private registry', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(registryFindings('.npmrc', 'registry=http://registry.example.invalid/')).toEqual([]);
  });

  it('emits nothing for an allowlisted https registry without userinfo', () => {
    process.env[FLAG] = '1';
    expect(
      registryFindings('.npmrc', 'registry=https://registry.example.invalid/', {
        allowlist: ['registry.example.invalid'],
      }),
    ).toEqual([]);
  });

  it('emits nothing for https with no allowlist and no userinfo', () => {
    process.env[FLAG] = '1';
    expect(registryFindings('.npmrc', 'registry=https://registry.example.invalid/')).toEqual([]);
  });

  it('reports http', () => {
    process.env[FLAG] = '1';
    const findings = registryFindings('.npmrc', 'registry=http://registry.example.invalid/');
    expect(findings.some((row) => row.severity === 'high' && row.message.includes('http'))).toBe(true);
  });

  it('reports embedded userinfo and redacts the token', () => {
    process.env[FLAG] = '1';
    const findings = registryFindings('.npmrc', 'registry=https://token@registry.example.invalid/');
    const json = JSON.stringify(findings);
    expect(json).not.toContain('token');
    expect(findings.some((row) => row.severity === 'high')).toBe(true);
    expect(json).toContain('redacted');
  });

  it('rejects allowInsecureRegistryHosts other than localhost and 127.0.0.1', () => {
    process.env[FLAG] = '1';
    expect(() => registryFindings('.npmrc', 'registry=http://registry.example.invalid/', {
      allowInsecureRegistryHosts: ['registry.example.invalid'],
    })).toThrow(FsError);
  });

  it('does not read the home file unless phase 139 is on', () => {
    process.env[FLAG] = '1';
    const home = 'registry=http://registry.example.invalid/';
    expect(readRegistrySources(null, home)).toEqual([]);
    process.env[PHASE_139_FLAG] = '1';
    expect(readRegistrySources(null, home).length).toBeGreaterThan(0);
  });

  it('does not import a network client', () => {
    const source = readFileSync(new URL('../../../src/phases/p367.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:http');
    expect(source).not.toContain('node:https');
  });

  it('accepts localhost, skips comments, and reports a host outside the allowlist', () => {
    process.env[FLAG] = '1';
    expect(assertInsecureHosts(['localhost', '127.0.0.1'])).toBeUndefined();
    expect(homeNpmrcAllowed()).toBe(false);
    const npmrc = [
      '',
      '# comment',
      '; also',
      'ignore=this',
      '@scope:registry=https://npm.example.invalid/',
      'registry=not a url',
      'registry=https://:secret@npm.example.invalid/extra',
      'registry=http://127.0.0.1:4873/',
    ].join('\n');
    const findings = registryFindings('.npmrc', npmrc, {
      allowlist: ['127.0.0.1:4873'],
      allowInsecureRegistryHosts: ['127.0.0.1'],
    });
    expect(findings.some((row) => row.severity === 'medium' && row.message.includes('npm.example.invalid'))).toBe(true);
    expect(findings.some((row) => row.message.includes('http ('))).toBe(false);
    expect(JSON.stringify(findings)).not.toContain('secret');
    expect(JSON.stringify(findings)).toContain('redacted');
    expect(readRegistrySources(null, null)).toEqual([]);
    expect(readRegistrySources('registry=https://npm.example.invalid/\n', null, { allowlist: ['other.example'] }).length).toBeGreaterThan(0);
    delete process.env[FLAG];
    expect(readRegistrySources('registry=http://registry.example.invalid/', null)).toEqual([]);
  });
});
