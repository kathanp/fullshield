import { afterEach, describe, expect, it } from 'vitest';

import {
  enabled,
  FLAG,
  satisfiesWitness,
  verifyFix,
  type VerifyInput,
  type WitnessRef,
} from '../../../src/phases/p421.js';

afterEach(() => {
  delete process.env[FLAG];
});

function witness(line: number): WitnessRef {
  return { ruleId: 'SAST-SQLI-001', file: 'src/db.js', line };
}

function input(over: Partial<VerifyInput> = {}): VerifyInput {
  return {
    witness: witness(1),
    before: 'db.query("SELECT " + name)',
    after: 'db.query("SELECT ?", [name])',
    baselineIds: ['SAST-SQLI-001'],
    ...over,
  };
}

describe('phase 421 fix verification', () => {
  it('returns the after text unchanged when the flag is off', () => {
    expect(enabled()).toBe(false);
    const request = input();
    expect(verifyFix(request)).toEqual({
      after: request.after,
      eligibleSafe: false,
      witnessFailed: false,
      failedRuleId: null,
      failedLine: null,
      baselineIds: request.baselineIds,
      commands: [],
      processes: [],
    });
  });

  it('marks a parameterized query safe and only on the witness line', () => {
    process.env[FLAG] = '1';
    const request = input();
    const result = verifyFix(request);
    expect(result.eligibleSafe).toBe(true);
    expect(result.witnessFailed).toBe(true);
    expect(result.failedRuleId).toBe('SAST-SQLI-001');
    expect(result.failedLine).toBe(1);
    expect(result.after).toBe(request.after);
    expect(result.baselineIds).toBe(request.baselineIds);
    expect(result.commands).toEqual([]);
    expect(result.processes).toEqual([]);
    const source = 'db.query("SELECT " + name)\ndb.query("SELECT ?", [name])';
    expect(satisfiesWitness(source, witness(2), 2)).toBe(true);
    expect(satisfiesWitness(source, witness(1), 2)).toBe(false);
  });

  it('does not mark a still-open sink or a refused edit safe', () => {
    process.env[FLAG] = '1';
    const open = verifyFix(input({ after: 'db.query("SELECT " + name)' }));
    expect(open.eligibleSafe).toBe(false);
    expect(open.witnessFailed).toBe(false);
    expect(open.failedRuleId).toBeNull();
    const interpolated = verifyFix(input({ after: 'db.query(`SELECT ${name}`)' }));
    expect(interpolated.witnessFailed).toBe(false);
    const refused = verifyFix(input({ refused: true }));
    expect(refused.eligibleSafe).toBe(false);
    expect(refused.witnessFailed).toBe(false);
    const otherRule = verifyFix(input({ witness: { ...witness(1), ruleId: 'SAST-XSS-001' } }));
    expect(otherRule.eligibleSafe).toBe(false);
  });
});
