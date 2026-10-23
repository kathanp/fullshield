import { afterEach, describe, expect, it } from 'vitest';

import { concatAbs, FLAG as ABS, lit, tainted } from '../../../src/phases/p278.js';
import * as phase from '../../../src/phases/p279.js';

afterEach(() => {
  delete process.env[phase.FLAG];
  delete process.env[ABS];
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

  it('classifies holes in quotes, identifiers, numbers, and unknown clients', () => {
    process.env[phase.FLAG] = '1';
    process.env[ABS] = '1';
    const hole = tainted(['request'], 'any');
    const digits = tainted(['request'], 'digits');
    expect(phase.sqlLexer(concatAbs(lit("select '"), hole)).some((token) => token.holeContext === 'quoted-literal')).toBe(true);
    expect(phase.sqlLexer(concatAbs(lit('select "'), hole)).some((token) => token.holeContext === 'quoted-literal')).toBe(true);
    expect(phase.classifySqlValue(concatAbs(lit('order by '), hole)).findings.some((row) => row.sqlContext === 'identifier')).toBe(true);
    expect(phase.classifySqlValue(concatAbs(lit('select * from '), hole), { dialectKnown: false }).findings.some((row) => row.sqlContext === 'fallback')).toBe(true);
    expect(phase.classifySqlValue(hole).findings.some((row) => row.sqlContext === 'whole-query')).toBe(true);
    expect(phase.classifySqlValue(concatAbs(lit('id = '), digits)).findings).toEqual([]);
    expect(phase.analyzeSql('???', { file: 'bad.js' }).queries).toEqual([]);
    const source = 'function run() { if (ok) { const q = req.query.id; db.query(q); } else pool.execute(req.query.id); saved = req.query.id; other.query(req.query.id); }';
    expect(phase.analyzeSql(source, { file: 'q.js' }).findings.length).toBeGreaterThan(0);
  });
});
