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
});
