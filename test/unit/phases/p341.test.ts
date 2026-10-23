import { afterEach, describe, expect, it } from 'vitest';

import { applyAllowFile, enabled, FLAG } from '../../../src/phases/p341.js';
import { secretEdges, secretFingerprint, type FingerprintFinding } from '../../../src/phases/p340.js';
import type { SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const formats: SecretFormat[] = [{
  id: 'synth',
  source: 'https://example.invalid/grammar',
  prefix: 'fsyn_',
  alphabet: 'A-Za-z0-9',
  length: 16,
  notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
}];

function finding(): FingerprintFinding {
  const edges = secretEdges(TOKEN);
  return {
    ruleId: 'SECRETS-FORMAT-001',
    fingerprint: secretFingerprint(TOKEN, 'SECRETS-FORMAT-001'),
    prefix: edges.prefix,
    suffix: edges.suffix,
    locations: [{ file: 'a.js', line: 1 }],
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 341 allowlist', () => {
  it('does not read the file when the flag is off', () => {
    let reads = 0;
    const rows = [finding()];
    expect(enabled()).toBe(false);
    expect(applyAllowFile(rows, () => { reads += 1; return '{}'; }, formats, ['SECRETS-FORMAT-001'], '2026-01-01')).toBe(rows);
    expect(reads).toBe(0);
  });

  it('removes a matching fingerprint and rejects a raw token', () => {
    process.env[FLAG] = '1';
    const row = finding();
    const allow = JSON.stringify({
      entries: [{ ...row, until: '2099-01-01', reason: 'fixture', locations: undefined }],
    });
    const cleaned = applyAllowFile([row], () => allow, formats, ['SECRETS-FORMAT-001'], '2026-01-01');
    expect(cleaned).toEqual([]);
    expect(() => applyAllowFile([row], () => JSON.stringify({ entries: [{ fingerprint: TOKEN, prefix: 'fsyn', suffix: 'MNOP', reason: 'no', ruleId: 'SECRETS-FORMAT-001' }] }), formats, ['SECRETS-FORMAT-001'], '2026-01-01')).toThrow(/FS-E341/);
  });

  it('does not suppress an expired entry or a prefix mismatch', () => {
    process.env[FLAG] = '1';
    const row = finding();
    const expired = JSON.stringify({ entries: [{ fingerprint: row.fingerprint, prefix: row.prefix, suffix: row.suffix, until: '2000-01-01', reason: 'old', ruleId: row.ruleId }] });
    expect(applyAllowFile([row], () => expired, formats, ['SECRETS-FORMAT-001'], '2026-01-01')).toHaveLength(1);
    const wrongPrefix = JSON.stringify({ entries: [{ fingerprint: row.fingerprint, prefix: 'nope', suffix: row.suffix, reason: 'mismatch', ruleId: row.ruleId }] });
    expect(applyAllowFile([row], () => wrongPrefix, formats, ['SECRETS-FORMAT-001'], '2026-01-01')).toHaveLength(1);
  });

  it('rejects a file that is not an entry list and a rule that is not known', () => {
    process.env[FLAG] = '1';
    const row = finding();
    expect(() => applyAllowFile([row], () => '{', formats, ['SECRETS-FORMAT-001'], '2026-01-01')).toThrow(/not JSON/);
    expect(() => applyAllowFile([row], () => JSON.stringify({ entries: 'no', nested: ['x', 1, null] }), formats, ['SECRETS-FORMAT-001'], '2026-01-01')).toThrow(/missing entries/);
    expect(() => applyAllowFile([row], () => JSON.stringify({ entries: [{}] }), formats, ['SECRETS-FORMAT-001'], '2026-01-01')).toThrow(/incomplete/);
    expect(() => applyAllowFile([row], () => JSON.stringify({ entries: [{ fingerprint: 'fp', prefix: 'pre', suffix: 'suf', reason: 'why', ruleId: 'NOPE' }] }), formats, ['SECRETS-FORMAT-001'], '2026-01-01')).toThrow(/unknown rule/);
    const forever = JSON.stringify({ entries: [{ fingerprint: row.fingerprint, prefix: row.prefix, suffix: row.suffix, reason: 'standing', ruleId: row.ruleId, until: 1 }] });
    expect(applyAllowFile([row], () => forever, formats, ['SECRETS-FORMAT-001'], '2026-01-01')).toEqual([]);
  });
});
