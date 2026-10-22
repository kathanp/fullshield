import { describe, expect, it } from 'vitest';

import { enabled, FsError, FLAG, loadSupplyPolicy, POLICY_FLAG } from '../../../src/phases/p378.js';

const valid = JSON.stringify({
  allowedRegistries: ['https://npm.example.invalid/'],
  allowedScriptCapabilities: [],
  pinMode: 'exact',
  secretAllow: ['SECRET-FORMAT'],
  privateRegistryHosts: ['npm.example.invalid'],
});

describe('phase 378 supply-chain policy', () => {
  it('does not read the file when the flag is off', () => {
    expect(enabled()).toBe(false);
    const loaded = loadSupplyPolicy('{', 'fullshield.policy.json');
    expect(loaded.ignored).toBe(true);
    expect(loaded.policy).toBeNull();
  });

  it('loads a valid file', () => {
    process.env[POLICY_FLAG] = '1';
    expect(enabled()).toBe(true);
    const loaded = loadSupplyPolicy(valid);
    expect(loaded.policy?.pinMode).toBe('exact');
    expect(loaded.policy?.privateRegistryHosts).toEqual(['npm.example.invalid']);
  });

  it('fails closed on an unknown key and produces no policy', () => {
    process.env[FLAG] = '1';
    expect(() => loadSupplyPolicy('{"notAKey":true}')).toThrow(FsError);
    try {
      loadSupplyPolicy('{"notAKey":true}');
    } catch (error) {
      expect(error).toBeInstanceOf(FsError);
      expect((error as FsError).message).toContain('notAKey');
      expect((error as FsError).code).toBe('FS-E');
    }
  });

  it('rejects a remote policy location', () => {
    process.env[FLAG] = '1';
    expect(() => loadSupplyPolicy(valid, 'https://example.invalid/policy.json')).toThrow(FsError);
  });

  it('treats a missing file as no policy', () => {
    process.env[FLAG] = '1';
    expect(loadSupplyPolicy(null).policy).toBeNull();
  });
});
