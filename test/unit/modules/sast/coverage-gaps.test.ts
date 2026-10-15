import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runSastOnText } from '../../../../src/modules/sast/engine.js';

async function has(code: string, ruleId: string): Promise<boolean> {
  return (await runSastOnText('fixture.js', code)).some((f) => f.ruleId === ruleId);
}

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SAST_GAPS';
const previous = process.env[FLAG];

describe('phase 27 SAST coverage gaps (experimental)', () => {
  beforeEach(() => {
    process.env[FLAG] = '1';
  });

  afterEach(() => {
    if (previous === undefined) delete process.env[FLAG];
    else process.env[FLAG] = previous;
  });

  describe('numeric SQL via existing query() sink (stable)', () => {
    it('flags unquoted numeric concatenation and LIMIT concat', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { db.query('SELECT * FROM t WHERE id = ' + req.query.id); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/u', (req, res) => { db.query('SELECT * FROM t LIMIT ' + req.query.n); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
    });
  });

  describe('ORM raw-query sinks', () => {
    it('flags Prisma $queryRawUnsafe / $executeRawUnsafe / Prisma.raw with tainted SQL', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { prisma.$queryRawUnsafe('SELECT * FROM t WHERE id = ' + req.query.id); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/u', (req, res) => { prisma.$executeRawUnsafe('DELETE FROM t WHERE id = ' + req.query.id); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/u', (req, res) => { prisma.$queryRaw(Prisma.raw('SELECT * FROM t WHERE id = ' + req.query.id)); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag Prisma $queryRaw tagged template (parameterized)', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { prisma.$queryRaw\`SELECT * FROM t WHERE id = \${req.query.id}\`; });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(false);
      await expect(
        has(
          `app.get('/u', (req, res) => { prisma.$executeRaw\`UPDATE t SET n = \${req.body.n}\`; });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(false);
    });

    it('flags Sequelize query concat and literal()', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { sequelize.query('SELECT * FROM t WHERE id = ' + req.query.id); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/u', (req, res) => { sequelize.query(literal('id = ' + req.query.id)); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag Sequelize query with bind replacements', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { sequelize.query('SELECT * FROM t WHERE id = ?', { replacements: [req.query.id] }); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(false);
    });

    it('flags knex.raw / whereRaw / orderByRaw with tainted SQL and no bindings', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { knex.raw('SELECT * FROM t WHERE id = ' + req.query.id); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/u', (req, res) => { knex('t').whereRaw('id = ' + req.query.id); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/u', (req, res) => { knex('t').orderByRaw(req.query.sort); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag knex.whereRaw with bindings array', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { knex('t').whereRaw('id = ?', [req.query.id]); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(false);
    });

    it('flags TypeORM query() and createQueryBuilder().where(concat)', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { dataSource.query('SELECT * FROM t WHERE id = ' + req.query.id); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/u', (req, res) => { dataSource.createQueryBuilder().select('t').from(T, 't').where('id = ' + req.query.id).getMany(); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag TypeORM where with named parameters', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { dataSource.createQueryBuilder().where('id = :id', { id: req.query.id }).getMany(); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(false);
    });

    it('flags drizzle sql.raw with tainted input', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { db.execute(sql.raw('SELECT * FROM t WHERE id = ' + req.query.id)); });`,
          'SAST-SQLI-001',
        ),
      ).resolves.toBe(true);
    });

    it('flags mongoose $where with a tainted string', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { User.find({ $where: 'this.n == ' + req.query.n }); });`,
          'SAST-NOSQLI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/u', (req, res) => { User.$where('this.n == ' + req.query.n); });`,
          'SAST-NOSQLI-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag mongoose find with a field equality object', async () => {
      await expect(
        has(
          `app.get('/u', (req, res) => { User.find({ name: String(req.query.name) }); });`,
          'SAST-NOSQLI-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('template-literal shell calls', () => {
    it('flags exec / execSync template literals with tainted interpolation', async () => {
      await expect(
        has(
          `const { exec } = require('child_process');\napp.post('/r', (req, res) => { exec(\`ping \${req.body.host}\`); });`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `const { execSync } = require('child_process');\napp.post('/r', (req, res) => { execSync(\`ls \${req.query.path}\`); });`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(true);
    });

    it('flags spawn(sh, [-c, template]) even without shell:true', async () => {
      await expect(
        has(
          `const { spawn } = require('child_process');\napp.post('/r', (req, res) => { spawn('sh', ['-c', \`ls \${req.body.cmd}\`]); });`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(true);
    });

    it('flags execa with shell:true tagged template', async () => {
      await expect(
        has(
          `const { execa } = require('execa');\napp.post('/r', (req, res) => { execa({ shell: true })\`ping \${req.body.host}\`; });`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(true);
    });

    it('flags zx $.raw and quote:false tagged templates, not default $', async () => {
      await expect(
        has(
          `app.post('/r', (req, res) => { $\`ls \${req.query.x}\`; });`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(false);
      await expect(
        has(
          `app.post('/r', (req, res) => { $.raw\`ls \${req.query.x}\`; });`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.post('/r', (req, res) => { $({ quote: false })\`ls \${req.query.x}\`; });`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag execFile with an argument array', async () => {
      await expect(
        has(
          `const { execFile } = require('child_process');\napp.post('/r', (req, res) => { execFile('ping', ['-c', '1', req.body.host]); });`,
          'SAST-CMDI-001',
        ),
      ).resolves.toBe(false);
    });
  });
});

describe('phase 27 SAST coverage gaps stay off without the flag', () => {
  beforeEach(() => {
    delete process.env[FLAG];
  });

  afterEach(() => {
    if (previous === undefined) delete process.env[FLAG];
    else process.env[FLAG] = previous;
  });

  it('does not flag Prisma $queryRawUnsafe or knex.raw without the experimental flag', async () => {
    await expect(
      has(
        `app.get('/u', (req, res) => { prisma.$queryRawUnsafe('SELECT * FROM t WHERE id = ' + req.query.id); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(false);
    await expect(
      has(
        `app.get('/u', (req, res) => { knex.raw('SELECT * FROM t WHERE id = ' + req.query.id); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(false);
  });

  it('does not flag spawn(sh, [-c]) or zx $.raw without the experimental flag', async () => {
    await expect(
      has(
        `const { spawn } = require('child_process');\napp.post('/r', (req, res) => { spawn('sh', ['-c', \`ls \${req.body.cmd}\`]); });`,
        'SAST-CMDI-001',
      ),
    ).resolves.toBe(false);
    await expect(
      has(
        `app.post('/r', (req, res) => { $.raw\`ls \${req.query.x}\`; });`,
        'SAST-CMDI-001',
      ),
    ).resolves.toBe(false);
  });

  it('still flags classic db.query concat (stable SQLI)', async () => {
    await expect(
      has(
        `app.get('/u', (req, res) => { db.query('SELECT * FROM t WHERE id = ' + req.query.id); });`,
        'SAST-SQLI-001',
      ),
    ).resolves.toBe(true);
  });
});
