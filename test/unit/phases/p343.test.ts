import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p343.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 343', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.scanEncrypted('a.txt', 'sk_abcdefgh', [])).toEqual([]);
  });

  it('covers a git-crypt blob and leaves ordinary text to the caller', () => {
    process.env[phase.FLAG] = '1';
    const blob = '\0GITCRYPT\0secret';
    expect(phase.encryptedSpans(blob)[0]?.end).toBe(blob.length);
    expect(phase.scanEncrypted('a.txt', 'hello', []).some((row) => row.ruleId === 'SECRETS-FORMAT-001')).toBe(false);
  });
});
