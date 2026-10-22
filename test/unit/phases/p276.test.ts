import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p276.js';

const source = 'function* gen() { yield req.query.id; }\nfunction run() { db.query(gen().next()); }\n';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 276', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeGenerators(source).findings).toEqual([]);
    expect(phase.generatorYieldCount(source)).toBe(0);
  });

  it('counts a yield and ignores a function with no generator', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.generatorYieldCount(source)).toBe(1);
    expect(phase.generatorYieldCount('function run() { return 1; }')).toBe(0);
    expect(phase.analyzeGenerators('function run() { db.query("1"); }').findings).toEqual([]);
  });
});
