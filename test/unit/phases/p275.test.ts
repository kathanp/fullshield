import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p275.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

const closure = `function run() { db.query(req.query.id); }
`;

describe('phase 275', () => {
  it('returns no findings when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeClosures(closure).findings).toEqual([]);
  });

  it('reports a request value at a query and ignores a literal', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeClosures(closure).findings.some((row) => row.sinkClass === 'sqli')).toBe(true);
    expect(phase.analyzeClosures('function run() { db.query("1"); }').findings).toEqual([]);
  });
});
