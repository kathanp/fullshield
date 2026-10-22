import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, loadRegistry, matchSecret, mergeFormatFindings, type SecretFormat } from '../../../src/phases/p332.js';

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
});
