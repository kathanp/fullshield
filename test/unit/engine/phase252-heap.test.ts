import { afterEach, describe, expect, it } from 'vitest';

import { HEAP_FLAG, collapseKeepsTaint, collapsePath, heapEnabled, heapFindings } from '../../../src/engine/heap.js';

afterEach(() => {
  delete process.env[HEAP_FLAG];
});

describe('phase 252 heap', () => {
  it('is off unless the flag is set', () => {
    expect(heapEnabled()).toBe(false);
    expect(heapFindings('const o = { bad: req.query.x }; db.query(o.bad);')).toEqual([]);
  });

  it('reports the tainted field and not the clean field on the same object', () => {
    process.env[HEAP_FLAG] = '1';
    const source = [
      'const o = { safe: 1, bad: req.query.x };',
      'db.query(sql + o.bad);',
      'db.query(sql + o.safe);',
    ].join('\n');
    const findings = heapFindings(source);
    expect(findings.map((row) => row.path)).toEqual(['o.bad']);
  });

  it('keeps taint when a depth-4 path collapses', () => {
    process.env[HEAP_FLAG] = '1';
    expect(collapsePath(['a', 'b', 'c', 'd'], 3)).toBe('a.b.c');
    expect(collapseKeepsTaint(['a', 'b', 'c', 'd'], true)).toBe(true);
    const source = [
      'const o = { a: { b: { c: { d: req.query.x } } } };',
      'db.query(o.a.b.c.d);',
    ].join('\n');
    expect(heapFindings(source).map((row) => row.path)).toEqual(['o.a.b.c']);
  });
});
