import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p278.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 278', () => {
  it('does not evaluate when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.evaluateProgram('function run() { return "a"; }')).toBeNull();
  });

  it('concatenates abstract strings and keeps a literal free of taint labels', () => {
    process.env[phase.FLAG] = '1';
    const joined = phase.concatAbs(phase.lit('a'), phase.tainted(['req'], 'any'));
    expect(phase.labelsOf(joined)).toContain('req');
    expect(phase.labelsOf(phase.lit('safe'))).toEqual([]);
  });
});
