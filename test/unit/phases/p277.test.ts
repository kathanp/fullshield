import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p277.js';

const query = 'function run() { db.query(req.query.id); }\n';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 277', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeReflect(query).findings).toEqual([]);
  });

  it('reports a request query and ignores a literal', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeReflect(query).findings.some((row) => row.sinkClass === 'sqli')).toBe(true);
    expect(phase.analyzeReflect('function run() { db.query("1"); }').findings).toEqual([]);
  });
});
