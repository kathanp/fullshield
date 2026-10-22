import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p283.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 283', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzePath('fs.readFile(req.query.p);').findings).toEqual([]);
  });

  it('reports a request path and ignores a literal path', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzePath('fs.readFile(req.query.p);').findings.length).toBeGreaterThan(0);
    expect(phase.analyzePath('fs.readFile("notes.txt");').findings).toEqual([]);
    expect(phase.projectTargetsWindows({})).toBe(false);
  });
});
