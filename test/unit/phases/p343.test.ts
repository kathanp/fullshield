import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p343.js';
import type { SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const formats: SecretFormat[] = [{
  id: 'synth', source: 'https://example.invalid/grammar', prefix: 'fsyn_', alphabet: 'A-Za-z0-9', length: 16, notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
}];


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

  it('ignores ENC and age spans and reports visible text beside them', () => {
    process.env[phase.FLAG] = '1';
    const age = '-----BEGIN AGE ENCRYPTED FILE-----\nsecret\n-----END AGE ENCRYPTED FILE-----';
    expect(phase.encryptedSpans(age)[0]?.start).toBe(0);
    expect(phase.encryptedSpans('unencrypted_suffix: _unencrypted\n').length).toBe(0);
    const text = `sops:\npassword: ENC[abc]\nplain: ${TOKEN}\nlastmodified: 1\n${age}\nENC[no-end`;
    const spans = phase.encryptedSpans(text);
    expect(spans.some((span) => text.slice(span.start, span.end) === 'ENC[abc]')).toBe(true);
    expect(spans.some((span) => text.slice(span.start, span.end).includes('BEGIN AGE'))).toBe(true);
    const findings = phase.scanEncrypted('a.yaml', text, formats);
    expect(findings.some((row) => row.ruleId === 'SECRETS-FORMAT-001' && row.witness === 'synth')).toBe(true);
    const random = 'abcdefghijklmnopqrstuvwxyz012345';
    expect(phase.scanEncrypted('a.txt', `sops:\nvisible ${random}`, []).some((row) => row.ruleId === 'SECRETS-ENTROPY-001')).toBe(true);
    expect(phase.scanEncrypted('a.txt', `sops:\n${TOKEN}`, formats).some((row) => row.ruleId === 'SECRETS-ENTROPY-001')).toBe(false);
  });
});
