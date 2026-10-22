import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p355.js';
import { FLAG as SCRIPT } from '../../../src/phases/p353.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

const shape: phase.MalwareShape = {
  id: 'npmrc-plus-url',
  source: 'https://example.invalid/shape',
  reviewed: false,
  fp: 'A legitimate script may read npm config.',
  parts: ['read-npmrc', 'build-url'],
  fixtureUrl: 'https://example.invalid/collect',
};

describe('phase 355', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.shapeFindings("fs.readFileSync('.npmrc');\nfetch('https://example.invalid/collect');", [shape])).toEqual([]);
  });

  it('matches a url shape and rejects an automation review', () => {
    process.env[phase.FLAG] = '1';
    process.env[SCRIPT] = '1';
    const source = "fs.readFileSync('.npmrc');\nfetch('https://example.invalid/collect');";
    const hit = phase.shapeFindings(source, [shape]);
    expect(hit[0]?.severity).toBe('info');
    expect(hit[0]?.message).toContain('not a named campaign');
    expect(phase.shapeFindings("fs.readFileSync('.npmrc');", [shape])).toEqual([]);
    expect(() => phase.reviewShapeGuard({ automation: true, reviewed: true })).toThrow(/human/);
    delete process.env[SCRIPT];
  });
});
