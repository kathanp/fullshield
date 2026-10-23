import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, hostAllowed, ssrfWrap } from '../../../src/phases/p411.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 411', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(ssrfWrap('dry-run', []).text).toBe('');
  });

  it('shows the helper and refuses apply on an empty list', () => {
    process.env[FLAG] = '1';
    const dry = ssrfWrap('dry-run', []);
    expect(dry.text).toContain('allowFetch');
    expect(dry.reason).toContain('fill the list');
    expect(dry.text.includes('example.invalid')).toBe(false);
    expect(ssrfWrap('apply', []).applied).toBe(false);
    const filled = ssrfWrap('apply', ['api.example']);
    expect(filled.applied).toBe(true);
    expect(filled.text).toContain('api.example');
    expect(hostAllowed('*')).toBe(false);
    expect(hostAllowed('')).toBe(false);
  });
});
