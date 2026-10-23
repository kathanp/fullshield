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

  it('keeps comments out of the model and ignores a schema with no body', () => {
    process.env[FLAG] = '1';
    const schema = 'model User {\n  id Int\n  // note\n  @@index([id])\n  role String\n}\n';
    expect(analyzePrisma('1;', schema).models[0]?.fields).toEqual(['id', 'role']);
    expect(analyzePrisma('1;', 'model User').events.map((event) => event.reason)).toEqual(['schema parse']);
    expect(analyzePrisma('???', schema)).toMatchObject({ findings: [], keySets: [], events: [] });
  });

  it('reports request aliases and skips numeric wrappers and non-object calls', () => {
    process.env[FLAG] = '1';
    const source = `
      query(req);
      prisma.findFirst({ where: body });
      prisma.update({ data: { role: 1, [name]: 2, ...rest } });
      prisma.create();
      prisma.findMany(1);
      prisma.delete();
      sql\`select \${request.query.x}\`;
      other\`select \${req.query.x}\`;
      (0, prisma.$queryRaw)\`select \${req.query.x}\`;
      prisma.$queryRaw\`select \${request.query.x + Number(request.query.n)}\`;
      prisma.$executeRawUnsafe(req.query.n + parseInt(request.query.n));
      prisma.raw(\`select \${req.query.x}\`);
      prisma.$queryRawUnsafe(request);
      prisma.$queryRawUnsafe(prefix + request.query.x);
    `;
    const result = analyzePrisma(source, SCHEMA, { file: 'q.js' });
    expect(result.findings.every((finding) => finding.file === 'q.js')).toBe(true);
    expect(result.findings.map((finding) => finding.sink)).toEqual(['operator', 'raw', 'raw', 'raw', 'raw']);
    expect(result.keySets[0]?.keys).toEqual(['role', 'name']);
    expect(analyzePrisma('prisma.$queryRawUnsafe(req.query.n + Number(req.query.n));', SCHEMA).findings).toEqual([]);
    expect(analyzePrisma('prisma.$queryRawUnsafe(parseInt(request.query.n) + request.query.n);', SCHEMA).findings).toEqual([]);
  });
});
