import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p273.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

const handlers = `const handlers = { q: function () { db.query(req.query.id); } };
function run() { handlers.q(); }
`;

describe('phase 273', () => {
  it('returns no edges when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeCallGraph(handlers).edges).toEqual([]);
  });

  it('records a literal handler edge and ignores an empty diff', () => {
    process.env[phase.FLAG] = '1';
    const graph = phase.analyzeCallGraph(handlers);
    expect(graph.edges.some((edge) => edge.target === 'q')).toBe(true);
    expect(phase.diffCallEdges(['a'], ['a'])).toEqual({ gained: [], lost: [] });
    expect(phase.diffCallEdges(['a'], ['b']).gained).toEqual(['b']);
  });

  it('resolves computed keys and records an unknown callee', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeCallGraph(':::').edges).toEqual([]);
    expect(phase.diffCallEdges(['a', 'b'], ['b']).lost).toEqual(['a']);
    const source = [
      'const handlers = {',
      '  q: function () { db.query(req.query.id + "x"); },',
      '  r: () => db.query(`${req.query.id}`),',
      '  s: function () { db.query("1"); },',
      '};',
      'function run(key) {',
      '  handlers.q();',
      '  handlers["r"]();',
      '  handlers[key]();',
      '  handlers[req.query.id]();',
      '  handlers.missing();',
      '  mystery();',
      '}',
      'run("q");',
      'run(req.query.id);',
    ].join('\n');
    const graph = phase.analyzeCallGraph(source);
    expect(graph.edges.some((edge) => edge.target === 'r')).toBe(true);
    expect(graph.events.length).toBeGreaterThan(0);
    delete process.env[phase.FLAG];
  });
});
