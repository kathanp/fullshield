import { describe, expect, it } from 'vitest';

import { analyzePointsTo, enabled, FLAG } from '../../../src/phases/p272.js';

const POSITIVE = `const { Pool } = require('pg');
function Wrapper(db) { this.db = db; }
function Service(wrap) { this.wrap = wrap; }
const pool = new Pool();
const w = new Wrapper(pool);
const s = new Service(w);
s.wrap.db.query('select');
`;

const NEGATIVE = `const obj = { query(s) { return s; } };
function Wrapper(db) { this.db = db; }
function Service(wrap) { this.wrap = wrap; }
const w = new Wrapper(obj);
const s = new Service(w);
s.wrap.db.query('select');
`;

// Context-insensitive: one factory allocation site holds both a pool and a plain object.
const MERGED = `const { Pool } = require('pg');
function factory(flag) {
  if (flag) return new Pool();
  return { query(s) { return s; } };
}
const client = factory(true);
client.query('x');
`;

const SMALL = `const a = {};
const b = a;
`;

describe('phase 272 points-to', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzePointsTo(POSITIVE).findings).toEqual([]);
  });

  it('resolves a SQL client stored through two constructors', () => {
    process.env[FLAG] = '1';
    const result = analyzePointsTo(POSITIVE);
    expect(result.events).toEqual([]);
    expect(result.findings.some((finding) => finding.sink === 'pg.Pool.query')).toBe(true);
    expect(result.calls.some((call) => call.sink && call.targetKinds.includes('pool'))).toBe(true);
  });

  it('does not treat a plain object query method as the pg sink', () => {
    process.env[FLAG] = '1';
    const result = analyzePointsTo(NEGATIVE);
    expect(result.findings).toEqual([]);
    expect(result.calls.some((call) => call.sink)).toBe(false);
    expect(result.calls.some((call) => call.targetKinds.includes('object'))).toBe(true);
  });

  it('merges both objects returned by one factory and does not crash on budget overflow', () => {
    process.env[FLAG] = '1';
    const merged = analyzePointsTo(MERGED);
    const call = merged.calls[0];
    expect(call?.sink).toBe(true);
    expect(call?.targetKinds).toEqual(expect.arrayContaining(['pool', 'object']));
    expect(() => analyzePointsTo(SMALL, { budget: 1 })).not.toThrow();
    const overflow = analyzePointsTo(SMALL, { budget: 1 });
    expect(overflow.events.map((event) => event.kind)).toEqual(['fixpoint-cap']);
    expect(overflow.calls.every((call) => call.sink === false)).toBe(true);
    expect(overflow.variables.a).toEqual(['unknown']);
  });
});
