import { describe, expect, it } from 'vitest';

import { classifySql, enabled, FLAG, runtimeRunner, SQL_VECTORS, staticRunner } from '../../../src/runtime/exp/p383.js';

describe('phase 383 SQL tokenizer', () => {
  it('does not emit when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(runtimeRunner(SQL_VECTORS[0]!).event).toBe(false);
  });

  it('agrees on the shared vectors in both runners', () => {
    process.env[FLAG] = '1';
    for (const vector of SQL_VECTORS) {
      expect(staticRunner(vector).event).toBe(vector.expectEvent);
      expect(runtimeRunner(vector).event).toBe(vector.expectEvent);
    }
  });

  it('records a missing dialect and uses the generic lexer', () => {
    const decision = classifySql({ dialect: 'other', before: "select '", hole: 'ada', bound: false, digits: false });
    expect(decision.dialectUsed).toBe('generic');
    expect(decision.missingDialect).toBe('other');
    expect(decision.event).toBe(false);
  });
});
