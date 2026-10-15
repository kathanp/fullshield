import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runConfigAstChecks } from '../../../../src/modules/config/astChecks.js';
import { runSastOnText } from '../../../../src/modules/sast/engine.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_CLASSES';

const PHASE29_RULE_IDS = [
  'SAST-REDOS-001',
  'SAST-DESER-001',
  'SAST-XXE-001',
  'SAST-UPLOAD-001',
  'SAST-COOKIE-001',
  'SAST-CSRF-001',
  'SAST-MASSASSIGN-001',
  'SAST-TIMING-001',
  'SAST-HASH-001',
  'SAST-GQL-001',
  'CONFIG-TRUSTPROXY-001',
] as const;

async function has(code: string, ruleId: string, filename = 'fixture.js'): Promise<boolean> {
  return (await runSastOnText(filename, code)).some((f) => f.ruleId === ruleId);
}

describe('Phase 29 — experimental vuln classes', () => {
  beforeEach(() => {
    process.env[FLAG] = '1';
  });
  afterEach(() => {
    delete process.env[FLAG];
  });

  it('registers scan --experimental-classes', () => {
    const program = createProgram();
    const scanCmd = program.commands.find((c) => c.name() === 'scan');
    expect(scanCmd).toBeDefined();
    expect(scanCmd!.options.map((o) => o.long)).toContain('--experimental-classes');
  });

  it('does not emit Phase 29 rule IDs when the flag is unset on fixture apps', async () => {
    delete process.env[FLAG];
    const vuln = await scan({
      cwd: join(process.cwd(), 'test', 'fixtures', 'vulnerable-app'),
      modules: ['sast', 'config'],
    });
    const clean = await scan({
      cwd: join(process.cwd(), 'test', 'fixtures', 'clean-app'),
      modules: ['sast', 'config'],
    });
    const ids = new Set([...vuln.findings, ...clean.findings].map((f) => f.ruleId));
    for (const id of PHASE29_RULE_IDS) {
      expect(ids.has(id), `default scan must not emit ${id}`).toBe(false);
    }
  });

  it('keeps clean-app at 0 high/critical with the flag on', async () => {
    const clean = await scan({
      cwd: join(process.cwd(), 'test', 'fixtures', 'clean-app'),
      modules: ['sast', 'config'],
    });
    expect(clean.findings.filter((f) => f.severity === 'high' || f.severity === 'critical')).toEqual([]);
  });

  describe('SAST-REDOS-001', () => {
    it('flags tainted input against nested quantifiers', async () => {
      await expect(
        has(`app.get('/x', (req, res) => { /(a+)+/.test(req.query.q); });`, 'SAST-REDOS-001'),
      ).resolves.toBe(true);
    });

    it('flags overlapping quantified alternation via new RegExp', async () => {
      await expect(
        has(
          `app.get('/x', (req, res) => { new RegExp('(a|aa)+').test(req.body.q); });`,
          'SAST-REDOS-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag a simple character-class regex on tainted input', async () => {
      await expect(
        has(
          `app.post('/run', (req, res) => { /^[a-z0-9.-]{1,253}$/i.test(String(req.body.host)); });`,
          'SAST-REDOS-001',
        ),
      ).resolves.toBe(false);
    });

    it('does not flag a nested regex on a literal', async () => {
      await expect(has(`/(a+)+/.test('aaa');`, 'SAST-REDOS-001')).resolves.toBe(false);
    });

    it('flags String.match and an assigned nested regex', async () => {
      await expect(
        has(`app.get('/x', (req, res) => { req.query.q.match(/(a+)+/); });`, 'SAST-REDOS-001'),
      ).resolves.toBe(true);
      await expect(
        has(
          `app.get('/x', (req, res) => { const re = new RegExp('(a+)*'); re.test(req.query.q); });`,
          'SAST-REDOS-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag when the flag is off', async () => {
      delete process.env[FLAG];
      await expect(
        has(`app.get('/x', (req, res) => { /(a+)+/.test(req.query.q); });`, 'SAST-REDOS-001'),
      ).resolves.toBe(false);
    });
  });

  describe('SAST-DESER-001', () => {
    it('flags node-serialize.unserialize of tainted input', async () => {
      await expect(
        has(
          `const s = require('node-serialize');\napp.post('/x', (req, res) => { s.unserialize(req.body.data); });`,
          'SAST-DESER-001',
        ),
      ).resolves.toBe(true);
    });

    it('flags js-yaml load with the full schema', async () => {
      await expect(
        has(
          `const yaml = require('js-yaml');\napp.post('/x', (req, res) => { yaml.load(req.body, { schema: yaml.DEFAULT_FULL_SCHEMA }); });`,
          'SAST-DESER-001',
        ),
      ).resolves.toBe(true);
    });

    it('flags funcster deserialize of tainted input', async () => {
      await expect(
        has(
          `const funcster = require('funcster');\napp.post('/x', (req, res) => { funcster.deepDeserialize(req.body); });`,
          'SAST-DESER-001',
        ),
      ).resolves.toBe(true);
    });

    it('flags serialize-javascript eval paths', async () => {
      await expect(
        has(
          `const serialize = require('serialize-javascript');\napp.post('/x', (req, res) => { eval('(' + serialize(req.body) + ')'); });`,
          'SAST-DESER-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag yaml.load with JSON_SCHEMA', async () => {
      await expect(
        has(
          `const yaml = require('js-yaml');\napp.post('/x', (req, res) => { yaml.load(req.body, { schema: yaml.JSON_SCHEMA }); });`,
          'SAST-DESER-001',
        ),
      ).resolves.toBe(false);
    });

    it('flags yaml.unsafeLoad and serialize-javascript unsafe: true', async () => {
      await expect(
        has(
          `const yaml = require('js-yaml');\napp.post('/x', (req, res) => { yaml.unsafeLoad(req.body); });`,
          'SAST-DESER-001',
        ),
      ).resolves.toBe(true);
      await expect(
        has(
          `const serialize = require('serialize-javascript');\nserialize(obj, { unsafe: true });`,
          'SAST-DESER-001',
        ),
      ).resolves.toBe(true);
    });
  });

  describe('SAST-XXE-001', () => {
    it('flags libxmljs parseXml with noent true on tainted input', async () => {
      await expect(
        has(
          `const libxmljs = require('libxmljs');\napp.post('/x', (req, res) => { libxmljs.parseXml(req.body.xml, { noent: true }); });`,
          'SAST-XXE-001',
        ),
      ).resolves.toBe(true);
    });

    it('flags xml2js custom entities on tainted input', async () => {
      await expect(
        has(
          `const xml2js = require('xml2js');\nconst sax = require('sax');\nsax.ENTITIES['xxe'] = 'file:///etc/passwd';\napp.post('/x', (req, res) => { xml2js.parseString(req.body.xml); });`,
          'SAST-XXE-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag libxmljs with noent false', async () => {
      await expect(
        has(
          `const libxmljs = require('libxmljs');\napp.post('/x', (req, res) => { libxmljs.parseXml(req.body.xml, { noent: false }); });`,
          'SAST-XXE-001',
        ),
      ).resolves.toBe(false);
    });

    it('flags parseXmlString with noent true', async () => {
      await expect(
        has(
          `app.post('/x', (req, res) => { parseXmlString(req.body.xml, { noent: true }); });`,
          'SAST-XXE-001',
        ),
      ).resolves.toBe(true);
    });
  });

  describe('SAST-UPLOAD-001', () => {
    it('flags multer without size or type limits', async () => {
      await expect(
        has(`const multer = require('multer');\napp.post('/u', multer({ dest: 'uploads/' }).single('f'));`, 'SAST-UPLOAD-001'),
      ).resolves.toBe(true);
    });

    it('flags originalname used in a filesystem path', async () => {
      await expect(
        has(
          `const fs = require('fs');\napp.post('/u', (req, res) => { fs.writeFile(req.file.originalname, req.file.buffer); });`,
          'SAST-UPLOAD-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag multer with limits and fileFilter', async () => {
      await expect(
        has(
          `const multer = require('multer');\napp.post('/u', multer({ dest: 'uploads/', limits: { fileSize: 1000 }, fileFilter: (req, file, cb) => cb(null, file.mimetype === 'image/png') }).single('f'));`,
          'SAST-UPLOAD-001',
        ),
      ).resolves.toBe(false);
    });

    it('flags busboy and IncomingForm without size or type limits', async () => {
      await expect(has(`busboy({ headers: req.headers });`, 'SAST-UPLOAD-001')).resolves.toBe(true);
      await expect(has(`new IncomingForm();`, 'SAST-UPLOAD-001')).resolves.toBe(true);
    });
  });

  describe('SAST-COOKIE-001', () => {
    it('flags res.cookie without httpOnly, secure, or sameSite', async () => {
      await expect(
        has(`app.get('/x', (req, res) => { res.cookie('sid', req.query.t); });`, 'SAST-COOKIE-001'),
      ).resolves.toBe(true);
    });

    it('flags express-session with a hardcoded secret', async () => {
      await expect(
        has(`const session = require('express-session');\napp.use(session({ secret: 'keyboard cat' }));`, 'SAST-COOKIE-001'),
      ).resolves.toBe(true);
    });

    it('does not flag cookies with httpOnly, secure, and sameSite', async () => {
      await expect(
        has(
          `app.get('/x', (req, res) => { res.cookie('sid', 't', { httpOnly: true, secure: true, sameSite: 'strict' }); });`,
          'SAST-COOKIE-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('SAST-CSRF-001', () => {
    it('flags cookie-auth POST without CSRF or sameSite', async () => {
      await expect(
        has(
          `const session = require('express-session');\napp.use(session({ secret: process.env.SESSION_SECRET }));\napp.post('/xfer', (req, res) => { res.send('ok'); });`,
          'SAST-CSRF-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag POST when csurf is applied', async () => {
      await expect(
        has(
          `const session = require('express-session');\nconst csrf = require('csurf');\napp.use(session({ secret: process.env.SESSION_SECRET, cookie: { sameSite: 'lax' } }));\napp.use(csrf());\napp.post('/xfer', (req, res) => { res.send('ok'); });`,
          'SAST-CSRF-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('SAST-MASSASSIGN-001', () => {
    it('flags Model.create(req.body)', async () => {
      await expect(has(`User.create(req.body);`, 'SAST-MASSASSIGN-001')).resolves.toBe(true);
    });

    it('flags Model.update(req.body)', async () => {
      await expect(has(`User.update(req.body);`, 'SAST-MASSASSIGN-001')).resolves.toBe(true);
    });

    it('flags Object.assign(user, req.body)', async () => {
      await expect(has(`Object.assign(user, req.body);`, 'SAST-MASSASSIGN-001')).resolves.toBe(true);
    });

    it('does not flag create after an allowlist or schema parse', async () => {
      await expect(
        has(`User.create(pick(req.body, ['name']));`, 'SAST-MASSASSIGN-001'),
      ).resolves.toBe(false);
      await expect(
        has(`User.create(schema.parse(req.body));`, 'SAST-MASSASSIGN-001'),
      ).resolves.toBe(false);
    });
  });

  describe('SAST-TIMING-001', () => {
    it('flags secret comparison with ===', async () => {
      await expect(
        has(
          `app.post('/x', (req, res) => { if (storedToken === req.body.token) res.send('ok'); });`,
          'SAST-TIMING-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag crypto.timingSafeEqual', async () => {
      await expect(
        has(
          `app.post('/x', (req, res) => { if (crypto.timingSafeEqual(Buffer.from(storedToken), Buffer.from(req.body.token))) res.send('ok'); });`,
          'SAST-TIMING-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('SAST-HASH-001', () => {
    it('flags bcrypt cost below 10', async () => {
      await expect(has(`bcrypt.hash(password, 8);`, 'SAST-HASH-001')).resolves.toBe(true);
      await expect(has(`bcrypt.genSalt(4);`, 'SAST-HASH-001')).resolves.toBe(true);
    });

    it('flags argon2 below OWASP memory minimum', async () => {
      await expect(
        has(`argon2.hash(password, { memoryCost: 1024, timeCost: 2 });`, 'SAST-HASH-001'),
      ).resolves.toBe(true);
    });

    it('flags pbkdf2 iterations below OWASP SHA-256 minimum', async () => {
      await expect(
        has(`crypto.pbkdf2(password, salt, 10000, 32, 'sha256', cb);`, 'SAST-HASH-001'),
      ).resolves.toBe(true);
    });

    it('does not flag bcrypt cost 12 or OWASP argon2/pbkdf2', async () => {
      await expect(has(`bcrypt.hash(password, 12);`, 'SAST-HASH-001')).resolves.toBe(false);
      await expect(
        has(`argon2.hash(password, { memoryCost: 19456, timeCost: 2 });`, 'SAST-HASH-001'),
      ).resolves.toBe(false);
      await expect(
        has(`crypto.pbkdf2(password, salt, 600000, 32, 'sha256', cb);`, 'SAST-HASH-001'),
      ).resolves.toBe(false);
    });
  });

  describe('SAST-GQL-001', () => {
    it('flags introspection enabled in production', async () => {
      await expect(
        has(
          `if (process.env.NODE_ENV === 'production') {\n  new ApolloServer({ typeDefs, resolvers, introspection: true });\n}`,
          'SAST-GQL-001',
        ),
      ).resolves.toBe(true);
    });

    it('flags GraphQL server with no depth or complexity limit', async () => {
      await expect(
        has(`new ApolloServer({ typeDefs, resolvers });`, 'SAST-GQL-001'),
      ).resolves.toBe(true);
      await expect(has(`graphqlHTTP({ schema });`, 'SAST-GQL-001')).resolves.toBe(true);
    });

    it('flags tainted resolver args reaching a query sink', async () => {
      await expect(
        has(
          `const resolvers = { Query: { user: (parent, args) => db.query('SELECT * FROM t WHERE id = ' + args.id) } };`,
          'SAST-GQL-001',
        ),
      ).resolves.toBe(true);
    });

    it('does not flag introspection off with a depth limit', async () => {
      await expect(
        has(
          `const depthLimit = require('graphql-depth-limit');\nnew ApolloServer({ introspection: false, validationRules: [depthLimit(7)] });`,
          'SAST-GQL-001',
        ),
      ).resolves.toBe(false);
    });
  });

  describe('CONFIG-TRUSTPROXY-001', () => {
    it('flags trust proxy true with IP rate limiting', async () => {
      const findings = await runConfigAstChecks(
        'server.js',
        `const rateLimit = require('express-rate-limit');\nconst app = express();\napp.set('trust proxy', true);\napp.use(rateLimit({ windowMs: 60000, max: 5 }));`,
      );
      expect(findings.some((f) => f.ruleId === 'CONFIG-TRUSTPROXY-001')).toBe(true);
    });

    it('flags app.enable trust proxy with slowDown', async () => {
      const findings = await runConfigAstChecks(
        'server.js',
        `const app = express();\napp.enable('trust proxy');\napp.use(slowDown({ windowMs: 60000 }));`,
      );
      expect(findings.some((f) => f.ruleId === 'CONFIG-TRUSTPROXY-001')).toBe(true);
    });

    it('does not flag trust proxy without rate limiting', async () => {
      const findings = await runConfigAstChecks(
        'server.js',
        `const app = express();\napp.set('trust proxy', true);\napp.get('/', (req, res) => res.send('ok'));`,
      );
      expect(findings.filter((f) => f.ruleId === 'CONFIG-TRUSTPROXY-001')).toEqual([]);
    });

    it('does not flag when the flag is off', async () => {
      delete process.env[FLAG];
      const findings = await runConfigAstChecks(
        'server.js',
        `const rateLimit = require('express-rate-limit');\nconst app = express();\napp.set('trust proxy', true);\napp.use(rateLimit({ windowMs: 60000, max: 5 }));`,
      );
      expect(findings.filter((f) => f.ruleId === 'CONFIG-TRUSTPROXY-001')).toEqual([]);
    });
  });
});
