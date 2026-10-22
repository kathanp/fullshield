import { afterEach, describe, expect, it } from 'vitest';

import { analyzeFastifySchema, enabled, FLAG } from '../../../src/phases/p292.js';

const SOURCE = `
fastify.addSchema({ $id: 'IntId', type: 'integer' });
fastify.get('/item', { schema: { querystring: { type: 'object', properties: {
  id: { $ref: 'IntId' },
  name: { type: 'string' },
  code: { type: 'string', pattern: 'a+' },
  zip: { type: 'string', pattern: '^[0-9]+$' },
  odd: { not: { type: 'string' } },
} } } }, (req) => {
  db.query(req.query.id);
  db.query(req.query.name);
  db.query(req.query.code);
  db.query(req.query.zip);
  db.query(req.query.odd);
});
`;

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 292 fastify schema', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeFastifySchema(SOURCE)).toEqual({ findings: [], events: [] });
  });

  it('drops integer and anchored fields and keeps the others', () => {
    process.env[FLAG] = '1';
    const result = analyzeFastifySchema(SOURCE);
    expect(result.findings.map((finding) => finding.field).sort()).toEqual(['code', 'name', 'odd']);
    expect(result.events.map((event) => event.reason)).toContain('not');
  });

  it('records coerceTypes from code and ignores a comment', () => {
    process.env[FLAG] = '1';
    const coerced = analyzeFastifySchema("fastify.get('/c', { schema: { querystring: { type: 'object', properties: { name: { type: 'string' } } } }, coerceTypes: true }, (req) => { db.query(req.query.name); });");
    expect(coerced.findings[0]).toMatchObject({ field: 'name', coerceTypes: true });
    const comment = analyzeFastifySchema("// coerceTypes: true\nfastify.get('/c', { schema: { querystring: { type: 'object', properties: { name: { type: 'string' } } } } }, (req) => { db.query(req.query.name); });");
    expect(comment.findings[0]?.coerceTypes).toBe(false);
  });
});
