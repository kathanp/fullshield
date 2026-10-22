import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, passwordFindings } from '../../../src/phases/p320.js';

const reset = {
  file: 'reset.js',
  line: 3,
  source: 'randomBytes' as const,
  bytes: 32,
  storedHashed: true,
  compare: 'timingSafeEqual' as const,
  inQuery: false,
};

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 320 passwords', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(passwordFindings([{ file: 'a.js', line: 1, field: 'password', tagged: true, hash: 'plain' }])).toEqual([]);
  });

  it('accepts bcrypt and reports direct assignment and sha1 separately', () => {
    process.env[FLAG] = '1';
    expect(passwordFindings([{ file: 'a.js', line: 1, field: 'password', tagged: true, hash: 'bcrypt' }])).toEqual([]);
    const plain = passwordFindings([{ file: 'a.js', line: 2, field: 'password', tagged: true, hash: 'plain' }]);
    expect(plain.map((row) => row.ruleId)).toEqual(['SAST-PASSWORD-PLAIN-001']);
    const weak = passwordFindings([{ file: 'a.js', line: 3, field: 'password', tagged: true, hash: 'sha1' }]);
    expect(weak.map((row) => row.ruleId)).toEqual(['SAST-PASSWORD-WEAK-001']);
  });

  it('reports a 16-byte token, ===, and a query token, and accepts timingSafeEqual', () => {
    process.env[FLAG] = '1';
    expect(passwordFindings([], [{ ...reset, bytes: 16 }]).map((row) => row.ruleId)).toContain('SAST-RESET-BYTES-001');
    expect(passwordFindings([], [{ ...reset, compare: 'equal' }]).map((row) => row.ruleId)).toContain('SAST-RESET-COMPARE-001');
    expect(passwordFindings([], [reset]).map((row) => row.ruleId)).not.toContain('SAST-RESET-COMPARE-001');
    expect(passwordFindings([], [{ ...reset, inQuery: true }]).map((row) => row.ruleId)).toContain('SAST-RESET-QUERY-001');
  });

  it('names the config skip and still reports a weak algorithm', () => {
    process.env[FLAG] = '1';
    const skipped = passwordFindings([{ file: 'a.js', line: 4, field: 'password', tagged: true, hash: 'sha1', configSkip: true }]);
    expect(skipped[0]?.witness).toBe('config-skip');
    expect(skipped.map((row) => row.ruleId)).not.toContain('SAST-PASSWORD-PLAIN-001');
  });
});
