import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p285.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 285', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeNarrowing('function run() { db.query(req.query.id); }').findings).toEqual([]);
  });

  it('reports an un-narrowed request query and ignores a number guard', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeNarrowing('function run() { db.query(req.query.id); }').findings.length).toBeGreaterThan(0);
    expect(phase.analyzeNarrowing('function run() { const x = req.query.id; if (typeof x !== "number") return; db.query(x); }').findings).toEqual([]);
    expect(phase.analyzeNarrowing('function run() { const x = req.query.id; const y = req.query.other; if (typeof y === "number") { db.query(x); } }').findings).toHaveLength(1);
  });

  it('narrows typeof, instanceof, booleans, and predicates', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeNarrowing(':::').findings).toEqual([]);
    const source = [
      'function run(req) {',
      '  let x = req.query.id;',
      '  x = 1;',
      '  const flag = x === true;',
      '  if (typeof x === "number") { db.query(x); }',
      '  if (typeof x == "number") { db.query(x + "a"); }',
      '  if (typeof x !== "boolean") return;',
      '  if (!(typeof x === "number")) { throw new Error("n"); }',
      '  if (x instanceof Date) { db.query(x); } else { db.query(req.query.id); }',
      '  if (x !== false) { db.query(`${x}`); }',
      '  if (Number.isInteger(x)) { db.query(x); }',
      '  if (Array.isArray(x)) { db.query(x); }',
      '  if (/^\\d+$/.test(x)) { db.query(x); }',
      '  switch (x) { case 1: db.query(x); break; default: db.query(req.query.id); }',
      '  db.query(...args);',
      '  return x;',
      '}',
    ].join('\n');
    expect(phase.analyzeNarrowing(source).findings.length).toBeGreaterThan(0);
    delete process.env[phase.FLAG];
  });
});
