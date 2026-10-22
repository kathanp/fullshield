import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p288.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 288', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeStoredLink('res.send("ok");').findings).toEqual([]);
  });

  it('does not report a literal response', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeStoredLink('res.send("ok");').findings).toEqual([]);
  });
});
