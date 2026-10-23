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

  it('follows yields, delegates, and object key iteration', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.generatorYieldCount(':::')).toBe(0);
    const source = [
      'function* other() { yield req.query.d; }',
      'function* rec() { yield* rec(); }',
      'function* gen() {',
      '  const x = req.query.id;',
      '  yield x;',
      '  yield;',
      '  if (cond) { yield req.query.a; } else yield req.query.b;',
      '  for (let i = 0; i < 1; i++) { yield i; }',
      '  while (cond) { yield req.query.c; }',
      '  yield* other();',
      '  yield* rec();',
      '}',
      'function run() {',
      '  for (const item of gen()) { db.query(item); }',
      '  for (const item of gen()) db.query(item);',
      '  for (const item of missing()) { db.query(item); }',
      '  const rows = gen();',
      '  db.query(rows);',
      '  db.query(Object.keys(req.query));',
      '  db.query(Object.values(safe));',
      '  db.query(`x${req.query.id}`);',
      '  db.query(a + b);',
      '  x = req.query.id;',
      '  db.query(x);',
      '  if (cond) { db.query(req.query.id); } else { db.query("1"); }',
      '  { db.query(req.query.id); }',
      '}',
    ].join('\n');
    const result = phase.analyzeGenerators(source);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some((row) => row.sqlContext === 'identifier')).toBe(true);
    delete process.env[phase.FLAG];
  });
});
