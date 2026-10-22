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

  it('walks loops, arrays, and deferred closures', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeClosures('function', { file: 'bad.js' }).findings).toEqual([]);
    const source = `
      function run(n) {
        var hoisted = 1;
        const list = [req.query.id, , ...[]];
        list.push(1);
        for (var k = 0; k < 2; k++) { hoisted = k; }
        for (let j = 0; j < 1; j++) { db.query(list[0]); }
        const flag = n === 1 ? req.query.id : 0;
        const fn = function (x) { return x; };
        const arrow = () => flag;
        setTimeout(fn);
        mystery(fn);
        hoisted = req.query.id;
        return ++n + arrow();
      }
    `;
    const result = phase.analyzeClosures(source, { file: 'app.js' });
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
