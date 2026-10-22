import { afterEach, describe, expect, it } from 'vitest';

import { analyzePrisma, enabled, FLAG } from '../../../src/phases/p298.js';

const SCHEMA = 'model User {\n  id Int @id\n  role String\n}\n';
const SOURCE = `
prisma.$queryRaw\`select \${'ok'}\`;
prisma.$queryRawUnsafe('select ' + req.query.x);
prisma.user.findMany({ where: req.body });
prisma.user.findMany({ where: { id: req.params.id } });
prisma.user.create({ data: { role: req.body.role } });
`;

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 298 prisma', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzePrisma(SOURCE, SCHEMA).findings).toEqual([]);
  });

  it('separates raw sql, operator keys, and a finite where', () => {
    process.env[FLAG] = '1';
    const result = analyzePrisma(SOURCE, SCHEMA);
    expect(result.models[0]?.fields).toEqual(expect.arrayContaining(['id', 'role']));
    expect(result.findings.map((finding) => finding.sink)).toEqual(['raw', 'operator']);
    expect(result.keySets[0]?.keys).toEqual(['role']);
  });

  it('emits one event and no models when the schema does not parse', () => {
    process.env[FLAG] = '1';
    const result = analyzePrisma('prisma.user.findMany({ where: req.body });', 'model User { id Int');
    expect(result.models).toEqual([]);
    expect(result.findings).toEqual([]);
    expect(result.events).toHaveLength(1);
  });
});
