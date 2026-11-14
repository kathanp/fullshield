import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runScan } from '../../../../src/core/engine.js';
import { CONTRACT_FLAG, scanContractSources, type ContractFile } from '../../../../src/modules/contract/index.js';

const saved = process.env[CONTRACT_FLAG];

afterEach(() => {
  if (saved === undefined) {delete process.env[CONTRACT_FLAG];}
  else {process.env[CONTRACT_FLAG] = saved;}
});

function ids(found: { ruleId: string; message: string }[], ruleId: string): string[] {
  return found.filter((item) => item.ruleId === ruleId).map((item) => item.message);
}

const SPEC = `
openapi: 3.0.0
info:
  description: a note that mentions /admin in prose
paths:
  /users:
    get:
      summary: list
    parameters:
      - name: q
        in: query
  /missing:
    get:
      summary: gone
`;

describe('3.10.0 contract module', () => {
  it('reports an Express spec path with no route and a route with no spec path', async () => {
    const files: ContractFile[] = [
      { file: 'openapi.yaml', source: SPEC },
      {
        file: 'app.js',
        source: `
          const express = require('express');
          const app = express();
          app.get('/users', () => {});
          app.post('/extra', () => {});
        `,
      },
    ];
    const found = await scanContractSources(files);
    expect(ids(found, 'CONTRACT-SPEC-001')).toContain('OpenAPI GET /missing has no registered route.');
    expect(ids(found, 'CONTRACT-ROUTE-001')).toContain('Registered POST /extra has no OpenAPI path.');
    expect(found.some((item) => item.message.includes('GET /users'))).toBe(false);
    expect(found.some((item) => item.message.includes('/admin'))).toBe(false);
    const mounted = await scanContractSources([
      { file: 'openapi.yaml', source: 'paths:\n  /api/users:\n    get:\n      summary: list\n' },
      {
        file: 'app.js',
        source: `
          const router = express.Router();
          router.get('/users', () => {});
          app.use('/api', router);
        `,
      },
    ]);
    expect(mounted).toEqual([]);
  });

  it('reports the same mismatch for Fastify and stays quiet when the method and path match', async () => {
    const mismatch = await scanContractSources([
      { file: 'openapi.yaml', source: SPEC },
      {
        file: 'app.js',
        source: `
          const fastify = require('fastify')();
          fastify.get('/users', async () => {});
          fastify.post('/extra', async () => {});
        `,
      },
    ]);
    expect(ids(mismatch, 'CONTRACT-SPEC-001')).toContain('OpenAPI GET /missing has no registered route.');
    expect(ids(mismatch, 'CONTRACT-ROUTE-001')).toContain('Registered POST /extra has no OpenAPI path.');
    const matched = await scanContractSources([
      {
        file: 'openapi.json',
        source: JSON.stringify({ paths: { '/users': { get: { parameters: [{ in: 'query', name: 'q' }] } } } }),
      },
      { file: 'app.js', source: `fastify.get('/users', async () => {});` },
    ]);
    expect(matched).toEqual([]);
  });

  it('compares Nest controller paths and stays quiet for a matched method', async () => {
    const found = await scanContractSources([
      { file: 'openapi.yaml', source: SPEC },
      {
        file: 'users.ts',
        source: `
          @Controller('users')
          class Users {
            @Get()
            list() {}
          }
          @Controller()
          class Extra {
            @Post('extra')
            add() {}
          }
        `,
      },
    ]);
    expect(ids(found, 'CONTRACT-SPEC-001')).toContain('OpenAPI GET /missing has no registered route.');
    expect(ids(found, 'CONTRACT-ROUTE-001')).toContain('Registered POST /extra has no OpenAPI path.');
    expect(found.some((item) => item.message.includes('GET /users'))).toBe(false);
  });

  it('compares Next route files, including a dynamic segment, and ignores Hono and Koa', async () => {
    const found = await scanContractSources([
      {
        file: 'openapi.yaml',
        source: `
          paths:
            /api/users/{id}:
              get:
                summary: one
            /api/missing:
              get:
                summary: gone
        `,
      },
      { file: 'app/api/users/[id]/route.ts', source: `export function GET() { return 1; }` },
      { file: 'app/(shop)/api/extra/route.ts', source: `export function POST() { return 1; }` },
      { file: 'hono.js', source: `import { Hono } from 'hono';\nconst app = new Hono();\napp.get('/only-hono', () => {});\n` },
      { file: 'koa.js', source: `const Koa = require('koa');\nconst Router = require('@koa/router');\nconst router = new Router();\nrouter.get('/only-koa', () => {});\n` },
    ]);
    expect(ids(found, 'CONTRACT-SPEC-001')).toContain('OpenAPI GET /api/missing has no registered route.');
    expect(ids(found, 'CONTRACT-ROUTE-001')).toContain('Registered POST /api/extra has no OpenAPI path.');
    expect(found.some((item) => item.message.includes('/only-hono') || item.message.includes('/only-koa'))).toBe(false);
    expect(found.some((item) => item.message.includes('/api/users/{id}'))).toBe(false);
  });

  it('stays quiet with no OpenAPI file, a broken OpenAPI file, or only the word /admin', async () => {
    const noSpec = await scanContractSources([
      { file: 'app.js', source: `app.get('/users', () => {});` },
    ]);
    const broken = await scanContractSources([
      { file: 'openapi.json', source: '{ not json' },
      { file: 'app.js', source: `app.get('/users', () => {});` },
    ]);
    const prose = await scanContractSources([
      { file: 'note.js', source: `const path = '/admin';` },
      { file: 'openapi.yaml', source: `paths:\n  /users:\n    get:\n      summary: ok\n` },
      { file: 'app.js', source: `app.get('/users', () => {});` },
    ]);
    expect(noSpec).toEqual([]);
    expect(broken).toEqual([]);
    expect(prose).toEqual([]);
  });

  it('normalizes params, all-routes, quoted YAML, and a root Next file', async () => {
    const param = await scanContractSources([
      { file: 'openapi.yaml', source: "paths:\n  '/users/{id}':\n    get:\n      summary: one\n" },
      {
        file: 'users.ts',
        source: `
          @Controller('users')
          class Users {
            @Get(':id')
            one() {}
          }
        `,
      },
    ]);
    expect(param).toEqual([]);
    const home = await scanContractSources([
      { file: 'openapi.yaml', source: 'paths:\n  /:\n    get:\n      summary: home\n' },
      {
        file: 'root.ts',
        source: `
          @Controller
          class Root {
            @Get()
            home() {}
          }
        `,
      },
    ]);
    expect(home).toEqual([]);
    const root = await scanContractSources([
      { file: 'openapi.json', source: '{"paths":{"/":{"get":{}}}}' },
      { file: 'app/route.ts', source: 'export function GET() { return 1; }' },
    ]);
    expect(root).toEqual([]);
    const all = await scanContractSources([
      { file: 'openapi.yaml', source: 'paths:\n  /all/:\n    get:\n      summary: one\n' },
      { file: 'app.js', source: `app.all('/all', () => {});` },
    ]);
    expect(all).toEqual([]);
    const skipped = await scanContractSources([
      { file: 'openapi.json', source: '{"paths":null}' },
      { file: 'app/(group)/route.ts', source: 'export function ALL() { return 1; }' },
      { file: 'bad.js', source: 'const = ;' },
      { file: 'app.js', source: `app.use('users', router);\nrouter.get('/z', () => {});` },
    ]);
    expect(ids(skipped, 'CONTRACT-ROUTE-001')).toContain('Registered GET /z has no OpenAPI path.');
    expect(skipped.some((item) => item.message.includes('ALL'))).toBe(false);
    const outside = await scanContractSources([
      {
        file: 'openapi.yaml',
        source: 'paths:\n  /users:\n    get:\n      summary: ok\n      get:\n        summary: nested\nother:\n  /admin:\n    get:\n      summary: no\n',
      },
      { file: 'app.js', source: `app.get('/users', () => {});` },
    ]);
    expect(outside.some((item) => item.message.includes('/admin'))).toBe(false);
    expect(outside.some((item) => item.message.includes('/users'))).toBe(false);
    const badItem = await scanContractSources([
      { file: 'openapi.json', source: '{"paths":{"/x":"nope","/users":{"get":{}}}}' },
      { file: 'app.js', source: `app.get('/users', () => {});` },
    ]);
    expect(badItem).toEqual([]);
    const nil = await scanContractSources([
      { file: 'openapi.json', source: 'null' },
      { file: 'app.js', source: `app.get('/n', () => {});` },
    ]);
    expect(ids(nil, 'CONTRACT-ROUTE-001')).toContain('Registered GET /n has no OpenAPI path.');
    const beforePath = await scanContractSources([
      {
        file: 'openapi.yaml',
        source: 'paths:\n  summary:\n    get:\n      summary: skip\n  /users:\n    get:\n      summary: ok\n    post:\n      summary: also\n    parameters:\n      name: q\n',
      },
      { file: 'app.js', source: `app.get('/users', () => {});` },
    ]);
    expect(ids(beforePath, 'CONTRACT-SPEC-001')).toContain('OpenAPI POST /users has no registered route.');
    expect(beforePath.some((item) => item.message.includes('GET /users'))).toBe(false);
  });

  it('stays off the default scan and stays quiet on clean-app with the flag on', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fs-contract-app-'));
    await writeFile(join(dir, 'openapi.yaml'), 'paths:\n  /missing:\n    get:\n      summary: gone\n', 'utf8');
    await writeFile(join(dir, 'app.js'), `app.post('/extra', () => {});\n`, 'utf8');
    await writeFile(join(dir, 'package.json'), '{"name":"a","version":"1.0.0"}\n', 'utf8');
    delete process.env[CONTRACT_FLAG];
    const off = await runScan({ cwd: dir, offline: true });
    expect(off.metadata.modulesRequested).toEqual(['deps', 'secrets', 'sast', 'config']);
    expect(off.findings.some((item) => item.ruleId.startsWith('CONTRACT-'))).toBe(false);
    process.env[CONTRACT_FLAG] = '1';
    const stillDefault = await runScan({ cwd: dir, offline: true });
    expect(stillDefault.metadata.modulesRequested).toEqual(['deps', 'secrets', 'sast', 'config']);
    expect(stillDefault.findings.some((item) => item.ruleId.startsWith('CONTRACT-'))).toBe(false);
    delete process.env[CONTRACT_FLAG];
    const flaggedOff = await runScan({ cwd: dir, modules: ['contract'], offline: true });
    expect(flaggedOff.findings).toEqual([]);
    process.env[CONTRACT_FLAG] = '1';
    const on = await runScan({ cwd: dir, modules: ['contract'], offline: true });
    expect(on.findings.map((item) => item.ruleId).sort()).toEqual(['CONTRACT-ROUTE-001', 'CONTRACT-SPEC-001']);
    const clean = await runScan({
      cwd: join(import.meta.dirname, '../../../fixtures/clean-app'),
      modules: ['contract'],
      offline: true,
    });
    expect(clean.findings).toEqual([]);
  });
});
