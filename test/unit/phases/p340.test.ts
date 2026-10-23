import { afterEach, describe, expect, it } from 'vitest';

import { dedupeSecrets, enabled, FLAG, scannerLog, secretEdges, secretFingerprint } from '../../../src/phases/p340.js';

const LEFT = 'abcdMIDDLE1wxyz';
const RIGHT = 'abcdMIDDLE2wxyz';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 340 fingerprints', () => {
  it('keeps one finding per location when the flag is off', () => {
    expect(enabled()).toBe(false);
    const rows = dedupeSecrets([
      { file: 'a.js', line: 1, secret: LEFT, ruleId: 'SECRETS-FORMAT-001' },
      { file: 'b.js', line: 2, secret: LEFT, ruleId: 'SECRETS-FORMAT-001' },
    ]);
    expect(rows).toHaveLength(2);
  });

  it('groups one secret across two files and keeps two secrets apart', () => {
    process.env[FLAG] = '1';
    const same = dedupeSecrets([
      { file: 'b.js', line: 2, secret: LEFT, ruleId: 'SECRETS-FORMAT-001' },
      { file: 'a.js', line: 1, secret: LEFT, ruleId: 'SECRETS-FORMAT-001' },
    ]);
    expect(same).toHaveLength(1);
    expect(same[0]?.locations).toHaveLength(2);
    const different = dedupeSecrets([
      { file: 'a.js', line: 1, secret: LEFT, ruleId: 'SECRETS-FORMAT-001' },
      { file: 'a.js', line: 2, secret: RIGHT, ruleId: 'SECRETS-FORMAT-001' },
    ]);
    expect(different).toHaveLength(2);
    expect(secretEdges(LEFT)).toEqual(secretEdges(RIGHT));
    expect(secretFingerprint(LEFT, 'SECRETS-FORMAT-001')).not.toBe(secretFingerprint(RIGHT, 'SECRETS-FORMAT-001'));
    expect(JSON.stringify(same)).not.toContain(LEFT);
    expect(scannerLog(same).join('\n')).not.toContain(LEFT);
  });
});
