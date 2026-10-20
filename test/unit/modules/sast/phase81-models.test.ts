import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import type { Finding } from '../../../../src/core/finding.js';

const vulnerableApp = join(import.meta.dirname, '../../../fixtures/vulnerable-app');
const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const catalogPath = join(import.meta.dirname, '../../../../models/index.json');
const dirs: string[] = [];

const PACKAGES = [
  'express',
  'express-validator',
  'joi',
  'yup',
  'zod',
  'validator',
  'dompurify',
  'sanitize-html',
  'helmet',
  'pg',
  'mysql2',
  'sqlite3',
  'better-sqlite3',
  'knex',
  'sequelize',
  'typeorm',
  'prisma',
  'mongoose',
  'mongodb',
  'child_process',
  'execa',
  'axios',
  'node-fetch',
  'undici',
  'got',
  'fs',
  'fs-extra',
  'path',
  'ejs',
  'pug',
  'handlebars',
  'nunjucks',
  'jsonwebtoken',
  'bcrypt',
] as const;

const BUILTINS = new Set(['child_process', 'fs', 'path']);

interface Row {
  package: string;
  versionRange: string;
  inRange: string;
  outRange: string;
  kind: 'source' | 'sink' | 'sanitizer' | 'validator';
  sinkClass: string;
  memberPath: string;
  ruleId: string;
  positive: string;
  negative: string;
  /** in-range flag-on result for ruleId */
  positiveEffect: 'suppressed' | 'reported' | 'absent';
  negativeEffect: 'reported' | 'absent';
}

function sqlRoute(middleware: string): string {
  return `app.post('/x', ${middleware}, (req, res) => {\n  db.query('SELECT ' + req.body.id);\n});\n`;
}

function sqlAfter(call: string): string {
  return `function handler(req) {\n  ${call};\n  db.query('SELECT ' + req.body.id);\n}\n`;
}

function xssAssign(call: string): string {
  return `function handler(req, res) {\n  const clean = ${call};\n  res.send('<p>' + clean + '</p>');\n}\n`;
}

const XSS_RAW = `function handler(req, res) {\n  res.send('<p>' + req.query.q + '</p>');\n}\n`;

function withImport(pkg: string, body: string): string {
  return `const imported = require('${pkg}');\n${body}`;
}

const ROWS: Row[] = [
  {
    package: 'express',
    versionRange: '^4.0.0 || ^5.0.0',
    inRange: '4.18.2',
    outRange: '3.0.0',
    kind: 'source',
    sinkClass: 'sqli',
    memberPath: 'req.get',
    ruleId: 'SAST-SQLI-001',
    positive: `db.query('SELECT ' + req.get('x-request-id'));\n`,
    negative: `db.query('SELECT 1');\n`,
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'express-validator',
    versionRange: '>=6.0.0 <8.0.0',
    inRange: '7.2.1',
    outRange: '5.0.0',
    kind: 'validator',
    sinkClass: 'sqli',
    memberPath: 'body().isInt',
    ruleId: 'SAST-SQLI-001',
    positive: sqlRoute(`body('id').isInt()`),
    negative: sqlRoute(`body('id').trim()`),
    positiveEffect: 'suppressed',
    negativeEffect: 'reported',
  },
  {
    package: 'joi',
    versionRange: '>=17.0.0 <18.0.0',
    inRange: '17.13.3',
    outRange: '16.0.0',
    kind: 'validator',
    sinkClass: 'sqli',
    memberPath: 'Joi.number().validate',
    ruleId: 'SAST-SQLI-001',
    positive: sqlAfter(`Joi.number().validate(req.body.id)`),
    negative: sqlAfter(`Joi.string().trim()`),
    positiveEffect: 'suppressed',
    negativeEffect: 'reported',
  },
  {
    package: 'yup',
    versionRange: '>=0.32.0 <2.0.0',
    inRange: '1.4.0',
    outRange: '0.31.0',
    kind: 'validator',
    sinkClass: 'sqli',
    memberPath: 'yup.number().validate',
    ruleId: 'SAST-SQLI-001',
    positive: sqlAfter(`yup.number().validate(req.body.id)`),
    negative: sqlAfter(`yup.string().trim()`),
    positiveEffect: 'suppressed',
    negativeEffect: 'reported',
  },
  {
    package: 'zod',
    versionRange: '>=3.0.0 <5.0.0',
    inRange: '3.23.8',
    outRange: '2.0.0',
    kind: 'validator',
    sinkClass: 'sqli',
    memberPath: 'z.number().parse',
    ruleId: 'SAST-SQLI-001',
    positive: sqlAfter(`z.number().parse(req.body.id)`),
    negative: sqlAfter(`z.string().trim()`),
    positiveEffect: 'suppressed',
    negativeEffect: 'reported',
  },
  {
    package: 'validator',
    versionRange: '>=13.0.0 <14.0.0',
    inRange: '13.12.0',
    outRange: '12.0.0',
    kind: 'validator',
    sinkClass: 'sqli',
    memberPath: 'validator.isInt',
    ruleId: 'SAST-SQLI-001',
    positive: sqlAfter(`validator.isInt(req.body.id)`),
    negative: sqlAfter(`validator.trim(req.body.id)`),
    positiveEffect: 'suppressed',
    negativeEffect: 'reported',
  },
  {
    package: 'dompurify',
    versionRange: '>=2.0.0 <4.0.0',
    inRange: '3.1.6',
    outRange: '1.0.0',
    kind: 'sanitizer',
    sinkClass: 'xss',
    memberPath: 'DOMPurify.sanitize',
    ruleId: 'SAST-XSS-001',
    positive: xssAssign(`DOMPurify.sanitize(req.query.q)`),
    negative: XSS_RAW,
    positiveEffect: 'absent',
    negativeEffect: 'reported',
  },
  {
    package: 'sanitize-html',
    versionRange: '>=2.0.0 <3.0.0',
    inRange: '2.13.0',
    outRange: '1.0.0',
    kind: 'sanitizer',
    sinkClass: 'xss',
    memberPath: 'sanitizeHtml',
    ruleId: 'SAST-XSS-001',
    positive: xssAssign(`sanitizeHtml(req.query.q)`),
    negative: XSS_RAW,
    positiveEffect: 'suppressed',
    negativeEffect: 'reported',
  },
  {
    package: 'helmet',
    versionRange: '>=4.0.0 <8.0.0',
    inRange: '7.1.0',
    outRange: '3.0.0',
    kind: 'sanitizer',
    sinkClass: 'xss',
    memberPath: 'helmet',
    ruleId: 'SAST-XSS-001',
    positive: `function handler(req, res) {\n  helmet();\n  res.send('ok');\n}\n`,
    negative: `function handler(req, res) {\n  helmet();\n  res.send('<p>' + req.query.q + '</p>');\n}\n`,
    positiveEffect: 'absent',
    negativeEffect: 'reported',
  },
  {
    package: 'pg',
    versionRange: '>=8.0.0 <9.0.0',
    inRange: '8.12.0',
    outRange: '7.0.0',
    kind: 'sink',
    sinkClass: 'sqli',
    memberPath: 'query',
    ruleId: 'SAST-SQLI-001',
    positive: withImport('pg', `db.query('SELECT ' + req.body.id);\n`),
    negative: withImport('pg', `db.query('SELECT 1');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'mysql2',
    versionRange: '>=3.0.0 <4.0.0',
    inRange: '3.11.0',
    outRange: '2.0.0',
    kind: 'sink',
    sinkClass: 'sqli',
    memberPath: 'query',
    ruleId: 'SAST-SQLI-001',
    positive: withImport('mysql2', `db.query('SELECT ' + req.body.id);\n`),
    negative: withImport('mysql2', `db.query('SELECT 1');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'sqlite3',
    versionRange: '>=5.0.0 <6.0.0',
    inRange: '5.1.7',
    outRange: '4.0.0',
    kind: 'sink',
    sinkClass: 'sqli',
    memberPath: 'run',
    ruleId: 'SAST-SQLI-001',
    positive: withImport('sqlite3', `db.run('SELECT ' + req.body.id);\n`),
    negative: withImport('sqlite3', `db.run('SELECT 1');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'better-sqlite3',
    versionRange: '>=9.0.0 <12.0.0',
    inRange: '11.3.0',
    outRange: '8.0.0',
    kind: 'sink',
    sinkClass: 'sqli',
    memberPath: 'prepare',
    ruleId: 'SAST-SQLI-001',
    positive: withImport('better-sqlite3', `db.prepare('SELECT ' + req.body.id);\n`),
    negative: withImport('better-sqlite3', `db.prepare('SELECT 1');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'knex',
    versionRange: '>=2.0.0 <4.0.0',
    inRange: '3.1.0',
    outRange: '1.0.0',
    kind: 'sink',
    sinkClass: 'sqli',
    memberPath: 'raw',
    ruleId: 'SAST-SQLI-001',
    positive: withImport('knex', `knex.raw('SELECT ' + req.body.id);\n`),
    negative: withImport('knex', `knex.raw('SELECT 1');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'sequelize',
    versionRange: '>=6.0.0 <7.0.0',
    inRange: '6.37.3',
    outRange: '5.0.0',
    kind: 'sink',
    sinkClass: 'sqli',
    memberPath: 'query',
    ruleId: 'SAST-SQLI-001',
    positive: withImport('sequelize', `db.query('SELECT ' + req.body.id);\n`),
    negative: withImport('sequelize', `db.query('SELECT 1');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'typeorm',
    versionRange: '>=0.3.0 <0.4.0',
    inRange: '0.3.20',
    outRange: '0.2.0',
    kind: 'sink',
    sinkClass: 'sqli',
    memberPath: 'query',
    ruleId: 'SAST-SQLI-001',
    positive: withImport('typeorm', `db.query('SELECT ' + req.body.id);\n`),
    negative: withImport('typeorm', `db.query('SELECT 1');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'prisma',
    versionRange: '>=5.0.0 <7.0.0',
    inRange: '5.20.0',
    outRange: '4.0.0',
    kind: 'sink',
    sinkClass: 'sqli',
    memberPath: '$queryRawUnsafe',
    ruleId: 'SAST-SQLI-001',
    positive: withImport('prisma', `prisma.$queryRawUnsafe('SELECT ' + req.body.id);\n`),
    negative: withImport('prisma', `prisma.$queryRawUnsafe('SELECT 1');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'mongoose',
    versionRange: '>=6.0.0 <9.0.0',
    inRange: '8.6.0',
    outRange: '5.0.0',
    kind: 'sink',
    sinkClass: 'nosqli',
    memberPath: 'find',
    ruleId: 'SAST-NOSQLI-001',
    positive: withImport('mongoose', `User.find(req.body);\n`),
    negative: withImport('mongoose', `User.find({ name: 'ada' });\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'mongodb',
    versionRange: '>=4.0.0 <7.0.0',
    inRange: '6.8.0',
    outRange: '3.0.0',
    kind: 'sink',
    sinkClass: 'nosqli',
    memberPath: 'find',
    ruleId: 'SAST-NOSQLI-001',
    positive: withImport('mongodb', `collection.find(req.body);\n`),
    negative: withImport('mongodb', `collection.find({ name: 'ada' });\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'child_process',
    versionRange: '>=18.0.0',
    inRange: '22.13.0',
    outRange: '16.0.0',
    kind: 'sink',
    sinkClass: 'cmdi',
    memberPath: 'exec',
    ruleId: 'SAST-CMDI-001',
    positive: withImport('child_process', `exec(req.body.cmd);\n`),
    negative: withImport('child_process', `exec('ls');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'execa',
    versionRange: '>=8.0.0 <9.0.0',
    inRange: '8.0.1',
    outRange: '5.0.0',
    kind: 'sink',
    sinkClass: 'cmdi',
    memberPath: 'execa',
    ruleId: 'SAST-CMDI-001',
    positive: withImport('execa', `execa(req.body.cmd);\n`),
    negative: withImport('execa', `execa('ls');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'axios',
    versionRange: '>=1.0.0 <2.0.0',
    inRange: '1.7.7',
    outRange: '0.27.0',
    kind: 'sink',
    sinkClass: 'ssrf',
    memberPath: 'axios.get',
    ruleId: 'SAST-SSRF-001',
    positive: withImport('axios', `axios.get(req.query.url);\n`),
    negative: withImport('axios', `axios.get('https://example.invalid');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'node-fetch',
    versionRange: '>=3.0.0 <4.0.0',
    inRange: '3.3.2',
    outRange: '2.0.0',
    kind: 'sink',
    sinkClass: 'ssrf',
    memberPath: 'fetch',
    ruleId: 'SAST-SSRF-001',
    positive: withImport('node-fetch', `fetch(req.query.url);\n`),
    negative: withImport('node-fetch', `fetch('https://example.invalid');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'undici',
    versionRange: '>=6.0.0 <8.0.0',
    inRange: '6.19.8',
    outRange: '5.0.0',
    kind: 'sink',
    sinkClass: 'ssrf',
    memberPath: 'undici.request',
    ruleId: 'SAST-SSRF-001',
    positive: withImport('undici', `undici.request(req.query.url);\n`),
    negative: withImport('undici', `undici.request('https://example.invalid');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'got',
    versionRange: '>=14.0.0 <15.0.0',
    inRange: '14.4.2',
    outRange: '11.0.0',
    kind: 'sink',
    sinkClass: 'ssrf',
    memberPath: 'got',
    ruleId: 'SAST-SSRF-001',
    positive: withImport('got', `got(req.query.url);\n`),
    negative: withImport('got', `got('https://example.invalid');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'fs',
    versionRange: '>=18.0.0',
    inRange: '22.13.0',
    outRange: '16.0.0',
    kind: 'sink',
    sinkClass: 'path',
    memberPath: 'readFile',
    ruleId: 'SAST-PATH-001',
    positive: withImport('fs', `readFile(req.query.file);\n`),
    negative: withImport('fs', `readFile('notes.txt');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'fs-extra',
    versionRange: '>=11.0.0 <12.0.0',
    inRange: '11.2.0',
    outRange: '10.0.0',
    kind: 'sink',
    sinkClass: 'path',
    memberPath: 'readFile',
    ruleId: 'SAST-PATH-001',
    positive: withImport('fs-extra', `readFile(req.query.file);\n`),
    negative: withImport('fs-extra', `readFile('notes.txt');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'path',
    versionRange: '>=18.0.0',
    inRange: '22.13.0',
    outRange: '16.0.0',
    kind: 'sanitizer',
    sinkClass: 'path',
    memberPath: 'path.basename',
    ruleId: 'SAST-PATH-001',
    positive: `function handler(req) {\n  const clean = path.basename(req.query.file);\n  readFile(clean);\n}\n`,
    negative: `function handler(req) {\n  const clean = path.join(req.query.file);\n  readFile(clean);\n}\n`,
    positiveEffect: 'suppressed',
    negativeEffect: 'reported',
  },
  {
    package: 'ejs',
    versionRange: '>=3.0.0 <4.0.0',
    inRange: '3.1.10',
    outRange: '2.0.0',
    kind: 'sink',
    sinkClass: 'xss',
    memberPath: 'ejs.render',
    ruleId: 'SAST-XSS-001',
    positive: withImport('ejs', `ejs.render(req.query.q);\n`),
    negative: withImport('ejs', `ejs.render('<p>ok</p>');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'pug',
    versionRange: '>=3.0.0 <4.0.0',
    inRange: '3.0.3',
    outRange: '2.0.0',
    kind: 'sink',
    sinkClass: 'xss',
    memberPath: 'pug.render',
    ruleId: 'SAST-XSS-001',
    positive: withImport('pug', `pug.render(req.query.q);\n`),
    negative: withImport('pug', `pug.render('p ok');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'handlebars',
    versionRange: '>=4.0.0 <5.0.0',
    inRange: '4.7.8',
    outRange: '3.0.0',
    kind: 'sink',
    sinkClass: 'xss',
    memberPath: 'Handlebars.compile',
    ruleId: 'SAST-XSS-001',
    positive: withImport('handlebars', `Handlebars.compile(req.query.q);\n`),
    negative: withImport('handlebars', `Handlebars.compile('<p>{{name}}</p>');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'nunjucks',
    versionRange: '>=3.0.0 <4.0.0',
    inRange: '3.2.4',
    outRange: '2.0.0',
    kind: 'sink',
    sinkClass: 'xss',
    memberPath: 'nunjucks.renderString',
    ruleId: 'SAST-XSS-001',
    positive: withImport('nunjucks', `nunjucks.renderString(req.query.q);\n`),
    negative: withImport('nunjucks', `nunjucks.renderString('<p>ok</p>');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'jsonwebtoken',
    versionRange: '>=9.0.0 <10.0.0',
    inRange: '9.0.2',
    outRange: '8.0.0',
    kind: 'sink',
    sinkClass: 'jwt',
    memberPath: 'jwt.verify',
    ruleId: 'SAST-JWT-001',
    positive: withImport('jsonwebtoken', `jwt.verify(req.query.token);\n`),
    negative: withImport('jsonwebtoken', `jwt.sign({ id: 1 }, 'secret');\n`),
    positiveEffect: 'reported',
    negativeEffect: 'absent',
  },
  {
    package: 'bcrypt',
    versionRange: '>=5.0.0 <6.0.0',
    inRange: '5.1.1',
    outRange: '4.0.0',
    kind: 'sanitizer',
    sinkClass: 'crypto',
    memberPath: 'bcrypt.hash',
    ruleId: 'SAST-CRYPTO-001',
    positive: `function checkPassword(req) {\n  const hash = bcrypt.hash(req.body.password);\n  return hash;\n}\n`,
    negative: `function checkPassword(req) {\n  crypto.createHash('md5').update(req.body.password);\n}\n`,
    positiveEffect: 'absent',
    negativeEffect: 'reported',
  },
];

function stable(findings: readonly Finding[]): string {
  const rows = findings.map((finding) => ({
    ruleId: finding.ruleId,
    file: finding.file ?? '',
    line: finding.line ?? 0,
    severity: finding.severity,
    message: finding.message,
    snippet: finding.snippet ?? '',
  }));
  rows.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return JSON.stringify(rows);
}

function hasRule(findings: readonly Finding[], ruleId: string): boolean {
  return findings.some((finding) => finding.ruleId === ruleId);
}

async function project(pkg: string, version: string | undefined, code: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fs-models-'));
  dirs.push(dir);
  const dependencies: Record<string, string> = {};
  const packages: Record<string, { version?: string; dependencies?: Record<string, string> }> = { '': {} };
  if (version !== undefined) {
    dependencies[pkg] = version;
    packages[''] = { dependencies: { [pkg]: version } };
    packages[`node_modules/${pkg}`] = { version };
  }
  await writeFile(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'model-fixture', version: '1.0.0', dependencies }),
  );
  await writeFile(
    join(dir, 'package-lock.json'),
    JSON.stringify({ name: 'model-fixture', lockfileVersion: 2, packages }),
  );
  await writeFile(join(dir, 'index.js'), code);
  return dir;
}

describe('phase 81 library model packs', () => {
  afterEach(async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_MODELS;
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('validates every pack in models/index.json', async () => {
    const raw = JSON.parse(await readFile(catalogPath, 'utf8')) as {
      fullshieldVersion?: string;
      entries?: Array<Record<string, unknown>>;
    };
    const pkg = JSON.parse(await readFile(join(import.meta.dirname, '../../../../package.json'), 'utf8')) as {
      version: string;
    };
    expect(raw.fullshieldVersion).toBe(pkg.version);
    const entries = raw.entries ?? [];
    const kinds = new Set(['source', 'sink', 'sanitizer', 'validator']);
    const classes = new Set(['sqli', 'nosqli', 'cmdi', 'path', 'xss', 'ssrf', 'redirect', 'eval', 'jwt', 'crypto', 'proto']);
    for (const entry of entries) {
      expect(typeof entry.package).toBe('string');
      expect(typeof entry.versionRange).toBe('string');
      expect(kinds.has(String(entry.kind))).toBe(true);
      expect(classes.has(String(entry.sinkClass))).toBe(true);
      expect(typeof entry.memberPath).toBe('string');
      expect(entry.memberPath).not.toMatch(/\s/);
      expect(Number.isInteger(entry.argumentIndex)).toBe(true);
      expect(entry.argumentIndex as number).toBeGreaterThanOrEqual(0);
      expect(entry.reference).toMatch(/^https?:\/\/\S+$/);
    }
    const seen = new Set(entries.map((entry) => entry.package));
    expect([...seen].sort()).toEqual([...PACKAGES].sort());
    for (const row of ROWS) {
      expect(
        entries.some(
          (entry) =>
            entry.package === row.package &&
            entry.versionRange === row.versionRange &&
            entry.kind === row.kind &&
            entry.sinkClass === row.sinkClass &&
            entry.memberPath === row.memberPath &&
            entry.argumentIndex === 0,
        ),
      ).toBe(true);
    }
  });

  it('keeps scan findings identical with the flag off', async () => {
    const vulnOff = await scan({ cwd: vulnerableApp, offline: true });
    const cleanOff = await scan({ cwd: cleanApp, offline: true });
    process.env.FULLSHIELD_EXPERIMENTAL_MODELS = '0';
    const vulnExplicit = await scan({ cwd: vulnerableApp, offline: true });
    const cleanExplicit = await scan({ cwd: cleanApp, offline: true });
    expect(stable(vulnExplicit.findings)).toBe(stable(vulnOff.findings));
    expect(stable(cleanExplicit.findings)).toBe(stable(cleanOff.findings));
    expect(vulnExplicit.suppressed).toBeUndefined();
    expect(cleanExplicit.suppressed).toBeUndefined();
    expect(vulnExplicit.metadata.info).toBeUndefined();
    expect(cleanOff.findings).toHaveLength(0);
  });

  it('keeps clean-app at 0 findings with the flag on', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_MODELS = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toHaveLength(0);
  });

  it('suppresses SQL after express-validator body().isInt() and not after trim()', async () => {
    const positive = await project('express-validator', '7.2.1', sqlRoute(`body('id').isInt()`));
    const trimmed = await project('express-validator', '7.2.1', sqlRoute(`body('id').trim()`));
    const chained = await project('express-validator', '7.2.1', sqlRoute(`body('id').trim().isInt()`));
    const other = await project('express-validator', '7.2.1', sqlRoute(`body('name').isInt()`));
    process.env.FULLSHIELD_EXPERIMENTAL_MODELS = '0';
    const off = await scan({ cwd: positive, modules: ['sast'] });
    expect(hasRule(off.findings, 'SAST-SQLI-001')).toBe(true);
    expect(off.suppressed).toBeUndefined();
    process.env.FULLSHIELD_EXPERIMENTAL_MODELS = '1';
    const on = await scan({ cwd: positive, modules: ['sast'] });
    expect(hasRule(on.findings, 'SAST-SQLI-001')).toBe(false);
    expect(on.suppressed?.some((finding) => finding.suppressedBy === 'model:express-validator')).toBe(true);
    const trimOn = await scan({ cwd: trimmed, modules: ['sast'] });
    expect(hasRule(trimOn.findings, 'SAST-SQLI-001')).toBe(true);
    expect(trimOn.suppressed ?? []).toHaveLength(0);
    const chainOn = await scan({ cwd: chained, modules: ['sast'] });
    expect(hasRule(chainOn.findings, 'SAST-SQLI-001')).toBe(false);
    const otherOn = await scan({ cwd: other, modules: ['sast'] });
    expect(hasRule(otherOn.findings, 'SAST-SQLI-001')).toBe(true);
  });

  it('follows an assignment alias and ignores statements that have no left-hand side', async () => {
    const source = withImport(
      'express-validator',
      [
        'const { body } = imported;',
        'function handler(req) {',
        '  if (req.ready) return;',
        '  let id;',
        '  id = req.body.id;',
        "  body('id').isInt();",
        "  db.query('SELECT ' + id);",
        '}',
        '',
      ].join('\n'),
    );
    const dir = await project('express-validator', '7.2.1', source);
    process.env.FULLSHIELD_EXPERIMENTAL_MODELS = '1';
    const result = await scan({ cwd: dir, modules: ['sast'] });
    expect(hasRule(result.findings, 'SAST-SQLI-001')).toBe(false);
    expect(result.suppressed?.some((row) => row.suppressedBy === 'model:express-validator')).toBe(true);
  });

  it('skips an out-of-range pack with one info line and does not suppress', async () => {
    const dir = await project('express-validator', '5.0.0', sqlRoute(`body('id').isInt()`));
    process.env.FULLSHIELD_EXPERIMENTAL_MODELS = '1';
    const result = await scan({ cwd: dir, modules: ['sast'] });
    expect(hasRule(result.findings, 'SAST-SQLI-001')).toBe(true);
    expect(result.metadata.info).toEqual([
      'model pack express-validator skipped: 5.0.0 is outside >=6.0.0 <8.0.0',
    ]);
  });

  it.each(ROWS)('$package positive and negative fixtures', async (row) => {
    const pin = BUILTINS.has(row.package) ? undefined : row.inRange;
    const positiveDir = await project(row.package, pin, row.positive);
    const negativeDir = await project(row.package, pin, row.negative);
    delete process.env.FULLSHIELD_EXPERIMENTAL_MODELS;
    const off = await scan({ cwd: positiveDir, modules: ['sast'] });
    process.env.FULLSHIELD_EXPERIMENTAL_MODELS = '1';
    const on = await scan({ cwd: positiveDir, modules: ['sast'] });
    const negative = await scan({ cwd: negativeDir, modules: ['sast'] });
    if (row.positiveEffect === 'suppressed') {
      expect(hasRule(off.findings, row.ruleId)).toBe(true);
      expect(hasRule(on.findings, row.ruleId)).toBe(false);
      expect(on.suppressed?.some((finding) => finding.suppressedBy === `model:${row.package}` && finding.ruleId === row.ruleId)).toBe(true);
    } else if (row.positiveEffect === 'reported') {
      expect(hasRule(on.findings, row.ruleId)).toBe(true);
      expect(on.suppressed?.some((finding) => finding.ruleId === row.ruleId) ?? false).toBe(false);
    } else {
      expect(hasRule(on.findings, row.ruleId)).toBe(false);
    }
    if (row.negativeEffect === 'reported') {
      expect(hasRule(negative.findings, row.ruleId)).toBe(true);
      expect(negative.suppressed?.some((finding) => finding.ruleId === row.ruleId) ?? false).toBe(false);
    } else {
      expect(hasRule(negative.findings, row.ruleId)).toBe(false);
    }
    const outDir = await project(row.package, row.outRange, row.positive);
    const skipped = await scan({ cwd: outDir, modules: ['sast'] });
    expect(skipped.metadata.info).toEqual([
      `model pack ${row.package} skipped: ${row.outRange} is outside ${row.versionRange}`,
    ]);
  });
});
