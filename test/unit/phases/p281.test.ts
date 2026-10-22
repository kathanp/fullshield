import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p281.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 281', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeUrl('fetch(req.query.url);').findings).toEqual([]);
  });

  it('reports a request fetch and ignores a literal url', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeUrl('fetch(req.query.url);').findings.length).toBeGreaterThan(0);
    expect(phase.analyzeUrl('fetch("https://example.invalid/a");').findings).toEqual([]);
  });
});
