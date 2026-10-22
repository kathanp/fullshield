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
});
