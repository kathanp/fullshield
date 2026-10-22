import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { EMPTY_SHA256, enabled, entropyFindings, FLAG, thresholdOwnership } from '../../../src/phases/p333.js';
import { MINIFIED_MIN_BYTES } from '../../../src/phases/p363.js';

const RANDOM = 'abcdefghijklmnopqrstuvwxyz012345';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 333 entropy', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(entropyFindings([{ span: RANDOM, file: 'a.js', line: 1 }])).toEqual([]);
  });

  it('reports a long random span and rejects color, uuid, empty sha256, and a dictionary word', () => {
    process.env[FLAG] = '1';
    const hit = entropyFindings([{ span: RANDOM, file: 'a.js', line: 1 }]);
    expect(hit).toHaveLength(1);
    expect(hit[0]?.witness).toContain('shannon-v2');
    expect(JSON.stringify(hit)).not.toContain(RANDOM);
    expect(entropyFindings([{ span: 'deadbeef', file: 'a.js', line: 1 }])).toEqual([]);
    expect(entropyFindings([{ span: '123e4567-e89b-12d3-a456-426614174000', file: 'a.js', line: 1 }])).toEqual([]);
    expect(entropyFindings([{ span: EMPTY_SHA256, file: 'a.js', line: 1 }])).toEqual([]);
    expect(entropyFindings([{ span: 'password', file: 'a.js', line: 1 }])).toEqual([]);
  });

  it('excludes a minified file and refuses an automation edit of the threshold file', () => {
    process.env[FLAG] = '1';
    const fileText = RANDOM.repeat(Math.ceil((MINIFIED_MIN_BYTES + 2) / RANDOM.length));
    expect(entropyFindings([{ span: RANDOM, file: 'app.js', line: 1, fileText }])).toEqual([]);
    expect(() => thresholdOwnership({ author: 'Cursor Agent', files: ['quality/entropy-thresholds.json'] })).toThrow(/human-owned/);
    expect(() => thresholdOwnership({ author: 'Ada', files: ['quality/entropy-thresholds.json'] })).not.toThrow();
    const source = readFileSync(new URL('../../../src/phases/p333.ts', import.meta.url), 'utf8');
    expect(source.includes('writeFile')).toBe(false);
  });
});
