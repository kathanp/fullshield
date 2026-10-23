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

  it('follows template arguments and skips enum fields', () => {
    process.env[FLAG] = '1';
    expect(analyzeGraphql(':::')).toEqual({ findings: [], routes: [], events: [] });
    const source = [
      'const resolvers = {',
      '  Query: {',
      '    user: (parent, args) => { db.query(`select ${args.id}`); },',
      '    kind(parent, args) { db.query(args.kind); },',
      '    bare: (parent) => parent,',
      '    short: (parent, args) => args.id,',
      '  },',
      '  skip: 1,',
      '};',
      'const schema = { kind: { enum: ["a"] }, other: { name: "x" } };',
      'const unused = 1;',
    ].join('\n');
    const result = analyzeGraphql(source);
    expect(result.findings.map((row) => row.route)).toEqual(['GRAPHQL Query.user']);
    expect(result.routes).toContain('GRAPHQL Query.kind');
    delete process.env[FLAG];
  });
});
