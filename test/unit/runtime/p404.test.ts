import { describe, expect, it } from 'vitest';

import { CONFIG_SCHEMA, enabled, FLAG, FsError, validateConfig } from '../../../src/runtime/exp/p404.js';

describe('phase 404 runtime config', () => {
  it('does not validate when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(validateConfig({ notAKey: true }).listen).toBe(true);
  });

  it('throws FS-E for an unknown key and does not listen', () => {
    process.env[FLAG] = '1';
    expect(() => validateConfig({ notAKey: true })).toThrow(FsError);
  });

  it('listens for a valid object and rejects the metadata address', () => {
    process.env[FLAG] = '1';
    expect(validateConfig({ mode: 'monitor', advisoryMaxAge: '48h' }).listen).toBe(true);
    expect(() => validateConfig({ ssrfAllow: ['169.254.169.254'] })).toThrow(/metadata/);
    expect(() => validateConfig({ mode: 'block', fraction: 0 })).toThrow(/monitor logger/);
    expect(() => validateConfig({ redis: 'redis' })).toThrow(/no URL/);
    expect(() => validateConfig({ redis: 'redis', redisUrl: '' })).toThrow(/no URL/);
    expect(validateConfig({ mode: 'block', fraction: 0, monitorLogger: true }).listen).toBe(true);
    expect(validateConfig({ redis: 'redis', redisUrl: 'redis://local' }).listen).toBe(true);
    expect(validateConfig({ ssrfAllow: ['10.0.0.1'] }).listen).toBe(true);
    expect(validateConfig({ ssrfAllow: 'nope' }).listen).toBe(true);
    expect(validateConfig({ mode: 'block', fraction: 1 }).listen).toBe(true);
  });

  it('uses one schema for a scanner fixture and a runtime fixture', () => {
    expect(CONFIG_SCHEMA.properties).toHaveProperty('advisoryMaxAge');
    expect(CONFIG_SCHEMA.properties).toHaveProperty('mode');
    expect(CONFIG_SCHEMA.additionalProperties).toBe(false);
  });
});
