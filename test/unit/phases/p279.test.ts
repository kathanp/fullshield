import { afterEach, describe, expect, it } from 'vitest';

import { lit } from '../../../src/phases/p278.js';
import * as phase from '../../../src/phases/p279.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 279', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeSql('db.query(req.query.id);').findings).toEqual([]);
    expect(phase.classifySqlValue(lit('select 1')).findings).toEqual([]);
  });

  it('lexes a literal query and does not report it as a hole', () => {
    process.env[phase.FLAG] = '1';
    const tokens = phase.sqlLexer(lit('select 1'));
    expect(tokens.length).toBeGreaterThan(0);
    expect(phase.classifySqlValue(lit('select 1')).findings).toEqual([]);
    expect(phase.analyzeSql('db.query("select 1");').findings).toEqual([]);
  });
});
