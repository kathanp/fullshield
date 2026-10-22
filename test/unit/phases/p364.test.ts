import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { binaryHosts, enabled, FLAG } from '../../../src/phases/p364.js';

describe('phase 364 binary hosts', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(
      binaryHosts('registry.npmjs.org', [{ path: 'binding.gyp', text: "url: 'https://files.example.invalid/a.tar'" }]),
    ).toEqual([]);
  });

  it('emits nothing for a gyp URL on the registry host', () => {
    process.env[FLAG] = '1';
    expect(
      binaryHosts('registry.npmjs.org', [{ path: 'binding.gyp', text: "url: 'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz'" }]),
    ).toEqual([]);
  });

  it('reports a URL on files.example.invalid and does not download', () => {
    process.env[FLAG] = '1';
    const findings = binaryHosts('registry.npmjs.org', [
      { path: 'binding.gyp', text: "url: 'https://files.example.invalid/prebuilt.tar.gz'" },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.host).toBe('files.example.invalid');
    expect(findings[0]?.file).toBe('binding.gyp');
    expect(findings[0]?.message).toContain('Allow it in policy');
    const source = readFileSync(new URL('../../../src/phases/p364.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:http');
    expect(source).not.toContain('node:https');
  });

  it('emits nothing for a binding.gyp with no URL', () => {
    process.env[FLAG] = '1';
    expect(binaryHosts('registry.npmjs.org', [{ path: 'binding.gyp', text: "{ 'targets': [] }" }])).toEqual([]);
  });
});
