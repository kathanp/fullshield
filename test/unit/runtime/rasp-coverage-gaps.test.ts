import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import {
  contextFromRequest,
  decideSink,
  disableRasp,
  enableRasp,
  enterRaspContext,
  scoreCorpusByKind,
  wrapKnownPackage,
} from '../../../src/runtime/rasp/index.js';

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures/rasp');
const attacks = JSON.parse(readFileSync(join(fixtureDir, 'attack-corpus.json'), 'utf8')) as {
  cases: Array<Record<string, unknown>>;
};
const benign = JSON.parse(readFileSync(join(fixtureDir, 'benign-corpus.json'), 'utf8')) as {
  cases: Array<Record<string, unknown>>;
};

afterEach(() => {
  disableRasp();
});

function countContext(cases: Array<Record<string, unknown>>, context: string): number {
  return cases.filter((c) => c.context === context).length;
}

describe('phase 27 RASP numeric SQL', () => {
  it('blocks extra tokens in an unquoted numeric position and allows a single number', () => {
    const attack = contextFromRequest({ query: { id: '1 OR 1=1' } });
    expect(decideSink('sql', 'SELECT * FROM t WHERE id = 1 OR 1=1', attack).block).toBe(true);
    const limit = contextFromRequest({ query: { n: '10; DROP TABLE t' } });
    expect(decideSink('sql', 'SELECT * FROM t LIMIT 10; DROP TABLE t', limit).block).toBe(true);
    const ok = contextFromRequest({ query: { id: '42' } });
    expect(decideSink('sql', 'SELECT * FROM t WHERE id = 42', ok).block).toBe(false);
  });
});

describe('phase 27 RASP ORM + $where hooks', () => {
  it('hooks prisma / sequelize / knex / typeorm / drizzle raw SQL without a real database', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const prisma = {
      PrismaClient: {
        prototype: {
          $queryRawUnsafe(sql: string) {
            return sql;
          },
          $executeRawUnsafe(sql: string) {
            return sql;
          },
        },
      },
      Prisma: {
        raw(sql: string) {
          return sql;
        },
      },
    };
    const sequelize = {
      Sequelize: {
        prototype: {
          query(sql: string) {
            return sql;
          },
        },
      },
      literal(sql: string) {
        return sql;
      },
    };
    function knex() {
      return undefined;
    }
    knex.raw = (sql: string) => sql;
    knex.Client = {
      prototype: {
        raw(sql: string) {
          return sql;
        },
        whereRaw(sql: string) {
          return sql;
        },
      },
    };
    const typeorm = {
      DataSource: {
        prototype: {
          query(sql: string) {
            return sql;
          },
        },
      },
      SelectQueryBuilder: {
        prototype: {
          where(sql: string) {
            return sql;
          },
        },
      },
    };
    const drizzle = {
      sql: {
        raw(sql: string) {
          return sql;
        },
      },
    };
    wrapKnownPackage('@prisma/client', prisma);
    wrapKnownPackage('sequelize', sequelize);
    wrapKnownPackage('knex', knex);
    wrapKnownPackage('typeorm', typeorm);
    wrapKnownPackage('drizzle-orm', drizzle);
    const payload = "' OR 1=1--";
    const run = (fn: () => unknown) =>
      enterRaspContext(contextFromRequest({ query: { q: payload } }), fn);
    expect(() =>
      run(() => prisma.PrismaClient.prototype.$queryRawUnsafe(`SELECT * FROM t WHERE n = '${payload}'`)),
    ).toThrow(/RASP-SQL-001/);
    expect(() =>
      run(() => prisma.PrismaClient.prototype.$executeRawUnsafe(`DELETE FROM t WHERE n = '${payload}'`)),
    ).toThrow(/RASP-SQL-001/);
    expect(() => run(() => prisma.Prisma.raw(`SELECT * FROM t WHERE n = '${payload}'`))).toThrow(
      /RASP-SQL-001/,
    );
    expect(() =>
      run(() => sequelize.Sequelize.prototype.query(`SELECT * FROM t WHERE n = '${payload}'`)),
    ).toThrow(/RASP-SQL-001/);
    expect(() => run(() => sequelize.literal(`n = '${payload}'`))).toThrow(/RASP-SQL-001/);
    expect(() => run(() => knex.raw(`SELECT * FROM t WHERE n = '${payload}'`))).toThrow(/RASP-SQL-001/);
    expect(() => run(() => knex.Client.prototype.whereRaw(`id = '${payload}'`))).toThrow(/RASP-SQL-001/);
    expect(() =>
      run(() => typeorm.DataSource.prototype.query(`SELECT * FROM t WHERE n = '${payload}'`)),
    ).toThrow(/RASP-SQL-001/);
    expect(() => run(() => drizzle.sql.raw(`SELECT * FROM t WHERE n = '${payload}'`))).toThrow(
      /RASP-SQL-001/,
    );
  });

  it('treats mongoose $where JS that is not a single token as a structure change', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const mongoose = {
      Query: {
        prototype: {
          $where(expr: string) {
            return expr;
          },
        },
      },
    };
    wrapKnownPackage('mongoose', mongoose);
    const payload = '1 || true';
    expect(() =>
      enterRaspContext(contextFromRequest({ query: { n: payload } }), () => {
        mongoose.Query.prototype.$where(`this.n == ${payload}`);
      }),
    ).toThrow(/RASP-NOSQL-001/);
    expect(
      decideSink('nosql', { $where: 'this.n == 1 || true' }, contextFromRequest({ query: { n: '1 || true' } }))
        .block,
    ).toBe(true);
    expect(
      decideSink('nosql', { $where: 'this.n == 42' }, contextFromRequest({ query: { n: '42' } })).block,
    ).toBe(false);
  });
});

describe('phase 27 corpus contexts', () => {
  it('adds ≥10 attack cases each for numeric-sql, orm-raw, and template-shell', () => {
    expect(countContext(attacks.cases, 'numeric-sql')).toBeGreaterThanOrEqual(10);
    expect(countContext(attacks.cases, 'orm-raw')).toBeGreaterThanOrEqual(10);
    expect(countContext(attacks.cases, 'template-shell')).toBeGreaterThanOrEqual(10);
  });

  it('blocks every new-context attack and none of the matching benign cases', () => {
    const extra = attacks.cases.filter(
      (c) => c.context === 'numeric-sql' || c.context === 'orm-raw' || c.context === 'template-shell',
    );
    const extraScore = scoreCorpusByKind(extra);
    expect(extraScore.blocked).toBe(extraScore.total);
    expect(extraScore.total).toBeGreaterThanOrEqual(30);
    const benignExtra = benign.cases.filter(
      (c) => c.context === 'numeric-sql' || c.context === 'orm-raw' || c.context === 'template-shell',
    );
    expect(benignExtra.length).toBeGreaterThan(0);
    expect(scoreCorpusByKind(benignExtra).blocked).toBe(0);
    expect(scoreCorpusByKind(benign.cases).blocked).toBe(0);
  });
});
