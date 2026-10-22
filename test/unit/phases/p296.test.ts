import { afterEach, describe, expect, it } from 'vitest';

import { analyzeGraphql, enabled, FLAG } from '../../../src/phases/p296.js';

const SOURCE = `
const document = '{ user }';
const resolvers = {
  Query: {
    user(parent, args) { db.query('select ' + args.id); },
    other(parent, args) { db.query('select 1'); },
  },
  Mutation: {
    set(parent, args) { db.query(args.kind); },
  },
};
const schema = { kind: { enum: ['a', 'b'] } };
`;

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 296 graphql', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeGraphql(SOURCE)).toEqual({ findings: [], routes: [], events: [] });
  });

  it('reports one field and keeps a field that the document does not name', () => {
    process.env[FLAG] = '1';
    const result = analyzeGraphql(SOURCE);
    expect(result.routes).toEqual(['GRAPHQL Query.user', 'GRAPHQL Query.other', 'GRAPHQL Mutation.set']);
    expect(result.findings.map((finding) => finding.route)).toEqual(['GRAPHQL Query.user']);
  });
});
