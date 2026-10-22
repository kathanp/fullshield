import { afterEach, describe, expect, it } from 'vitest';

import { baselineKey, enabled, FLAG, legacyBaselineKey, normalizeIdentifiers, type FingerprintInput } from '../../../src/phases/p428.js';

afterEach(() => {
  delete process.env[FLAG];
});

function sample(over: Partial<FingerprintInput> = {}): FingerprintInput {
  return {
    ruleId: 'SAST-SQLI-001',
    sinkClass: 'sql',
    origin: 'req',
    file: 'src/db.js',
    line: 3,
    witnessShape: 'db.query("SELECT " + userId)',
    ...over,
  };
}

describe('phase 428 stable fingerprints', () => {
  it('keeps the rule, file, and line key when the flag is off', () => {
    expect(enabled()).toBe(false);
    const row = sample({ witnessShape: 'completely different', line: 9 });
    expect(baselineKey(row)).toBe(legacyBaselineKey(row.ruleId, row.file, row.line));
    expect(baselineKey(row)).toBe('SAST-SQLI-001\u0000src/db.js\u00009');
  });

  it('hashes the normalized shape and ignores the line', () => {
    process.env[FLAG] = '1';
    const left = sample();
    const right = sample({ line: 40, witnessShape: 'conn.query("SELECT " + name)' });
    expect(normalizeIdentifiers(left.witnessShape)).toBe('v1.v2("SELECT " + v3)');
    expect(normalizeIdentifiers('return user')).toBe('return v1');
    expect(baselineKey(right)).toBe(baselineKey(left));
    expect(baselineKey(right)).not.toBe(legacyBaselineKey(left.ruleId, left.file, left.line));
  });

  it('changes the key when the string literal or file changes', () => {
    process.env[FLAG] = '1';
    const left = sample();
    expect(baselineKey(sample({ witnessShape: 'db.query("SELECT * " + userId)' }))).not.toBe(baselineKey(left));
    expect(baselineKey(sample({ file: 'src/other.js' }))).not.toBe(baselineKey(left));
  });
});
