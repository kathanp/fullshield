import { describe, expect, it } from 'vitest';

import { enabled, FLAG, graphqlGuard, graphqlStatic } from '../../../src/runtime/exp/p399.js';

function deep(levels: number): string {
  let doc = 'query { ';
  for (let i = 0; i < levels; i += 1) {
    doc += `f${i} { `;
  }
  doc += 'leaf';
  doc += ' }'.repeat(levels + 1);
  return doc;
}

describe('phase 399 graphql caps', () => {
  it('does not reject when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(graphqlGuard(deep(30), { depth: 2, fields: 2 }).reject).toBe(false);
  });

  it('rejects a document deeper than the cap and accepts a shallow one', () => {
    process.env[FLAG] = '1';
    expect(graphqlGuard(deep(4), { depth: 2, fields: 200 }).reject).toBe(true);
    expect(graphqlGuard('{ hero }', { depth: 12, fields: 200 }).reject).toBe(false);
  });

  it('counts one per field, including introspection, and reports info when no cap is visible', () => {
    process.env[FLAG] = '1';
    const counted = graphqlGuard('{ __schema { types } }', { depth: 12, fields: 1 });
    expect(counted.fields).toBeGreaterThan(1);
    expect(counted.reject).toBe(true);
    const finding = graphqlStatic('type Query { hero: String } # graphql', null);
    expect(finding?.severity).toBe('info');
  });
});
