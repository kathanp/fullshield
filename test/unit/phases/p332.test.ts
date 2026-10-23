import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { alphabetSet, enabled, FLAG, loadRegistry, matchGrammar, matchSecret, mergeFormatFindings, validateFormat, type SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';

function row(over: Partial<SecretFormat> = {}): SecretFormat {
  return {
    id: 'synth',
    source: 'https://example.invalid/grammar',
    prefix: 'fsyn_',
    alphabet: 'A-Za-z0-9',
    length: 16,
    notBeforeLength: 21,
    synthetic: [{ value: TOKEN, synthetic: true }],
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 332 secret formats', () => {
  it('does not match and leaves existing rule ids when the flag is off', () => {
    const existing = [{ ruleId: 'SECRETS-AWS-001' }];
    expect(enabled()).toBe(false);
    expect(matchSecret(TOKEN, [row()])).toBeUndefined();
    expect(mergeFormatFindings(existing)).toBe(existing);
  });

  it('matches a supplied synthetic example and rejects the wrong length', () => {
    process.env[FLAG] = '1';
    expect(matchSecret(TOKEN, [row()])?.id).toBe('synth');
    expect(matchSecret('fsyn_example', [row()])).toBeUndefined();
    expect(matchSecret('fsyn_ABCDEFGHIJKLMNO', [row()])).toBeUndefined();
  });

  it('fails a row that is missing source and refuses an absent registry', () => {
    process.env[FLAG] = '1';
    const missing = { ...row(), source: '' };
    expect(loadRegistry([missing]).ok).toBe(false);
    expect(loadRegistry(undefined).reason).toContain('human must supply');
    const source = readFileSync(new URL('../../../src/phases/p332.ts', import.meta.url), 'utf8');
    expect(source.includes(TOKEN)).toBe(false);
  });

  it('loads a checksum row and skips an inverted alphabet', () => {
    expect(enabled()).toBe(false);
    expect(loadRegistry([row()]).formats).toEqual([]);
    process.env[FLAG] = '1';
    expect(alphabetSet('A-C_')).toEqual(new Set(['A', 'B', 'C', '_']));
    expect(alphabetSet('B-A')).toBeUndefined();
    expect(validateFormat(null)).toEqual(['row']);
    expect(validateFormat({
      id: '',
      source: ' ',
      prefix: 1,
      alphabet: 'B-A',
      length: 'x',
      synthetic: [{}],
    })).toEqual(expect.arrayContaining(['id', 'source', 'grammar', 'length', 'synthetic']));
    const summed = row({
      id: 'sum',
      prefix: 'z',
      alphabet: 'AB',
      length: 2,
      notBeforeLength: 3,
      checksum: { algorithm: 'sum-mod', mod: 10, residue: 1 },
      synthetic: [{ value: 'zAB', synthetic: true }],
    });
    const loaded = loadRegistry([summed, { ...summed, checksum: { algorithm: 'other' } }]);
    expect(loaded.ok).toBe(true);
    expect(loaded.formats[0]?.checksum).toEqual({ algorithm: 'sum-mod', mod: 10, residue: 1 });
    expect(loaded.formats[1]?.checksum).toBeUndefined();
    expect(matchGrammar('zAB', loaded.formats)?.checksum).toBe(true);
    expect(matchGrammar('zAA', [summed])).toBeUndefined();
    expect(matchGrammar('zzAB', [summed])?.synthetic).toBe(true);
    expect(matchSecret('zAB', [row({ alphabet: 'B-A' }), summed])?.id).toBe('sum');
    expect(loadRegistry([{ ...summed, id: '' }]).ok).toBe(false);
  });
});
