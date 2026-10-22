import { afterEach, describe, expect, it } from 'vitest';

import { debugFindings, enabled, FLAG } from '../../../src/phases/p329.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 329 debug routes', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(debugFindings([{ file: 'a.js', line: 1, fullPath: '/metrics', authKind: 'none' }])).toEqual([]);
  });

  it('rates unauthenticated metrics as medium and skips an authenticated route', () => {
    process.env[FLAG] = '1';
    expect(debugFindings([{ file: 'a.js', line: 1, fullPath: '/metrics', authKind: 'none' }])[0]?.severity).toBe('medium');
    expect(debugFindings([{ file: 'a.js', line: 1, fullPath: '/metrics', authKind: 'session' }])).toEqual([]);
  });

  it('rates development docs as info and does not match documentation', () => {
    process.env[FLAG] = '1';
    expect(debugFindings([{ file: 'a.js', line: 2, fullPath: '/docs', authKind: 'none', env: 'development' }])[0]?.severity).toBe('info');
    expect(debugFindings([{ file: 'a.js', line: 3, fullPath: '/documentation', authKind: 'none' }])).toEqual([]);
  });
});
