import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, snapshotFindings } from '../../../src/phases/p336.js';
import { secretEdges, secretFingerprint } from '../../../src/phases/p340.js';
import type { SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const body = TOKEN.slice('fsyn_'.length);

function residue(value: string): number {
  let sum = 0;
  for (const char of value) {
    sum += char.codePointAt(0) ?? 0;
  }
  return sum % 97;
}

const prefixOnly: SecretFormat = {
  id: 'synth',
  source: 'https://example.invalid/grammar',
  prefix: 'fsyn_',
  alphabet: 'A-Za-z0-9',
  length: 16,
  notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
};

const checksummed: SecretFormat = { ...prefixOnly, checksum: { algorithm: 'sum-mod', mod: 97, residue: residue(body) } };

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 336 snapshots', () => {
  it('emits nothing when the flag is off or the snapshot has no match', () => {
    expect(enabled()).toBe(false);
    expect(snapshotFindings('app/__snapshots__/a.snap', TOKEN, [prefixOnly])).toEqual([]);
    process.env[FLAG] = '1';
    expect(snapshotFindings('app/__snapshots__/a.snap', 'plain', [prefixOnly])).toEqual([]);
  });

  it('drops a prefix-only snapshot to info and keeps a checksummed snapshot high', () => {
    process.env[FLAG] = '1';
    expect(snapshotFindings('app/__snapshots__/a.snap', TOKEN, [prefixOnly])[0]?.severity).toBe('info');
    expect(snapshotFindings('app/__snapshots__/a.snap', TOKEN, [checksummed])[0]?.severity).toBe('high');
  });

  it('drops an allowlisted fingerprint', () => {
    process.env[FLAG] = '1';
    const edges = secretEdges(TOKEN);
    const allow = [{ fingerprint: secretFingerprint(TOKEN, 'SECRETS-FORMAT-001'), prefix: edges.prefix, suffix: edges.suffix, ruleId: 'SECRETS-FORMAT-001' }];
    expect(snapshotFindings('app/__snapshots__/a.snap', TOKEN, [prefixOnly], allow)).toEqual([]);
  });
});
