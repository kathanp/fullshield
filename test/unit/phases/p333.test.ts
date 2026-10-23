import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { EMPTY_SHA256, enabled, entropyFindings, entropyReject, FLAG, isMinifiedDensity, shannon, thresholdOwnership } from '../../../src/phases/p333.js';
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

  it('rejects an empty span, a short file, a matched format, and a low-entropy span', () => {
    process.env[FLAG] = '1';
    expect(shannon('')).toBe(0);
    expect(shannon('aa')).toBe(0);
    expect(isMinifiedDensity('short')).toBe(false);
    expect(isMinifiedDensity('a\n'.repeat(30_000))).toBe(false);
    expect(entropyReject({ span: RANDOM, file: 'a.js', line: 1, formatMatched: true })).toBe('format');
    expect(entropyReject({ span: 'abc', file: 'a.js', line: 1 })).toBe('hex-color');
    expect(entropyReject({ span: 'abcdefff', file: 'a.js', line: 1 })).toBe('hex-color');
    expect(entropyReject({ span: 'aaaa', file: 'a.js', line: 1 })).toBe('below-threshold');
    expect(entropyFindings([{ span: '   ', file: 'a.js', line: 1 }])).toEqual([]);
    expect(() => thresholdOwnership({ author: 'automation bot', files: ['quality\\entropy-thresholds.json'] })).toThrow(/human-owned/);
    expect(() => thresholdOwnership({ author: 'cursor', files: ['src/app.ts'] })).not.toThrow();
  });
});
