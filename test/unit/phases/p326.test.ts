import { afterEach, describe, expect, it } from 'vitest';

import { apiKeyFindings, enabled, FLAG, type ApiKeyRead } from '../../../src/phases/p326.js';

function read(over: Partial<ApiKeyRead> = {}): ApiKeyRead {
  return { file: 'a.js', line: 1, from: 'query', name: 'apiKey', reachesCompare: true, ...over };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 326 api key query', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(apiKeyFindings([read()])).toEqual([]);
  });

  it('reports a query apiKey used as auth and ignores a header and q', () => {
    process.env[FLAG] = '1';
    expect(apiKeyFindings([read()])[0]?.severity).toBe('medium');
    expect(apiKeyFindings([read({ from: 'header', name: 'Authorization' })])).toEqual([]);
    expect(apiKeyFindings([read({ name: 'q' })])).toEqual([]);
  });

  it('marks a name-only match as low', () => {
    process.env[FLAG] = '1';
    const findings = apiKeyFindings([read({ reachesCompare: false })]);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.message).toContain('by name');
  });
});
