import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { ScanResult } from '../../../src/core/engine.js';
import type { Finding } from '../../../src/core/finding.js';
import { withSectionH } from '../../../src/exp/sectionh.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECTIONG';
const made: string[] = [];

afterEach(async () => {
  delete process.env[FLAG];
  await Promise.all(made.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function root(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'sectionh-'));
  made.push(dir);
  return dir;
}

async function put(dir: string, name: string, text: string): Promise<void> {
  const path = join(dir, name);
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, text);
}

async function scan(dir: string): Promise<ScanResult> {
  process.env[FLAG] = '1';
  return withSectionH({ findings: [] } as unknown as ScanResult, dir);
}

function rule(result: ScanResult, n: string): Finding | undefined {
  return result.findings.find((row) => row.ruleId === ['SECT', 'H', n].join('-'));
}

describe('phase 572 section H', () => {
  it('adds nothing when the flag is off', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'app.listen(3000);\n');
    const result = await withSectionH({ findings: [] } as unknown as ScanResult, dir);
    expect(result.findings).toEqual([]);
  });

  it('adds nothing on clean-app when the flag is on', async () => {
    const result = await scan(join(process.cwd(), 'test/fixtures/clean-app'));
    expect(result.findings).toEqual([]);
  });

  it('reports a hidden character in javascript and ignores ascii', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'const name = "a\u202eb";\n');
    expect(rule(await scan(dir), '001')?.severity).toBe('medium');
    await put(dir, 'a.js', 'const name = "ab";\n');
    expect(rule(await scan(dir), '001')).toBeUndefined();
  });

  it('reports a hidden character in a lockfile url and ignores an ascii url', async () => {
    const dir = await root();
    await put(dir, 'package-lock.json', '{"packages":{},"url":"https://example.com/\u200b"}\n');
    expect(rule(await scan(dir), '001')).toBeDefined();
    await put(dir, 'package-lock.json', '{"packages":{},"url":"https://example.com/"}\n');
    expect(rule(await scan(dir), '001')).toBeUndefined();
  });

  it('reports lockfiles that disagree and ignores one lockfile', async () => {
    const dir = await root();
    await put(dir, 'package-lock.json', '{"packages":{"node_modules/left-pad":{"version":"1.0.0"}}}\n');
    await put(dir, 'yarn.lock', 'left-pad@^1.0.0:\n  version "2.0.0"\n');
    expect(rule(await scan(dir), '005')?.message).toContain('left-pad');
    await rm(join(dir, 'yarn.lock'));
    expect(rule(await scan(dir), '005')).toBeUndefined();
    await put(dir, 'pnpm-lock.yaml', 'packages:\n  /left-pad@2.0.0:\n');
    expect(rule(await scan(dir), '005')).toBeDefined();
  });

  it('reports a patch that sinks request data and ignores a version patch', async () => {
    const dir = await root();
    await put(dir, 'patches/left.js', 'db.query(req.body.name);\n');
    expect(rule(await scan(dir), '007')?.severity).toBe('medium');
    await put(dir, 'patches/left.js', 'version 1.2.3\n');
    expect(rule(await scan(dir), '007')).toBeUndefined();
  });

  it('reports a packed private path and ignores dist', async () => {
    const dir = await root();
    await put(dir, 'package.json', '{"files":[".env"]}\n');
    expect(rule(await scan(dir), '008')?.severity).toBe('medium');
    await put(dir, 'package.json', '{"files":["dist"]}\n');
    expect(rule(await scan(dir), '008')).toBeUndefined();
    await put(dir, '.npmignore', '.env\n');
    expect(rule(await scan(dir), '008')).toBeDefined();
    await put(dir, '.npmignore', '!.env\n');
    expect(rule(await scan(dir), '008')).toBeUndefined();
  });

  it('reports a public workspace and ignores private true', async () => {
    const dir = await root();
    await put(dir, 'package.json', '{"name":"@acme/widget","workspaces":["@acme/widget"]}\n');
    expect(rule(await scan(dir), '009')).toBeDefined();
    await put(dir, 'package.json', '{"name":"@acme/widget","private":true,"workspaces":["@acme/widget"]}\n');
    expect(rule(await scan(dir), '009')).toBeUndefined();
  });

  it('reports curl in an install script and ignores node', async () => {
    const dir = await root();
    await put(dir, 'package.json', '{"scripts":{"postinstall":"curl https://example.com/x"}}\n');
    expect(rule(await scan(dir), '010')?.severity).toBe('medium');
    await put(dir, 'package.json', '{"scripts":{"postinstall":"node build.js"}}\n');
    expect(rule(await scan(dir), '010')).toBeUndefined();
  });

  it('reports a config download without a hash and ignores application source', async () => {
    const dir = await root();
    await put(dir, 'download.config.json', '{"url":"https://example.com/tool"}\n');
    expect(rule(await scan(dir), '011')).toBeDefined();
    await put(dir, 'download.config.json', '{"url":"https://example.com/tool","sha256":"aa"}\n');
    expect(rule(await scan(dir), '011')).toBeUndefined();
    await put(dir, 'app.js', "fetch('https://example.com/health');\n");
    expect(rule(await scan(dir), '011')).toBeUndefined();
  });

  it('reports a loader in a script and ignores a plain start', async () => {
    const dir = await root();
    await put(dir, 'package.json', '{"scripts":{"start":"NODE_OPTIONS=--require ./hook.js node server.js"}}\n');
    expect(rule(await scan(dir), '012')).toBeDefined();
    await put(dir, 'package.json', '{"scripts":{"start":"node server.js"}}\n');
    expect(rule(await scan(dir), '012')).toBeUndefined();
  });

  it('reports node major drift and ignores the same major', async () => {
    const dir = await root();
    await put(dir, 'package.json', '{"engines":{"node":">=22"}}\n');
    await put(dir, '.nvmrc', '24\n');
    expect(rule(await scan(dir), '013')).toBeDefined();
    await put(dir, '.nvmrc', '22\n');
    expect(rule(await scan(dir), '013')).toBeUndefined();
  });

  it('reports a production import of a devDependency', async () => {
    const dir = await root();
    await put(dir, 'package.json', '{"dependencies":{"express":"1.0.0"},"devDependencies":{"lodash":"1.0.0"}}\n');
    await put(dir, 'app.js', "const lodash = require('lodash');\n");
    expect(rule(await scan(dir), '014')).toBeDefined();
    await put(dir, 'app.js', "const express = require('express');\n");
    expect(rule(await scan(dir), '014')).toBeUndefined();
  });

  it('reports a types major skew and ignores the same major', async () => {
    const dir = await root();
    await put(dir, 'package-lock.json', '{"packages":{"node_modules/@types/lodash":{"version":"3.0.0"},"node_modules/lodash":{"version":"4.17.21"}}}\n');
    expect(rule(await scan(dir), '015')).toBeDefined();
    await put(dir, 'package-lock.json', '{"packages":{"node_modules/@types/lodash":{"version":"4.0.0"},"node_modules/lodash":{"version":"4.17.21"}}}\n');
    expect(rule(await scan(dir), '015')).toBeUndefined();
  });

  it('reports a raw query and ignores a placeholder', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'const knex = require("knex");\nknex.raw(req.body.q);\n');
    expect(rule(await scan(dir), '016')?.severity).toBe('medium');
    await put(dir, 'a.js', 'const knex = require("knex");\nknex.raw("select $1", [req.body.q]);\n');
    expect(rule(await scan(dir), '016')).toBeUndefined();
    await put(dir, 'a.js', 'sequelize.query(req.body.q);\n');
    expect(rule(await scan(dir), '016')).toBeDefined();
    await put(dir, 'a.js', 'typeorm\ncreateQueryBuilder(req.body.q);\n');
    expect(rule(await scan(dir), '016')).toBeDefined();
  });

  it('reports a mongo query and ignores a literal', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'mongoose\nUser.where(req.query.q);\n');
    expect(rule(await scan(dir), '017')?.severity).toBe('medium');
    await put(dir, 'a.js', 'mongoose\nUser.where({ id: 1 });\n');
    expect(rule(await scan(dir), '017')).toBeUndefined();
  });

  it('reports a socket payload and ignores a literal send', async () => {
    const dir = await root();
    await put(dir, 'a.js', "socket.on('message', (msg) => db.query(msg));\n");
    expect(rule(await scan(dir), '018')).toBeDefined();
    await put(dir, 'a.js', "socket.on('message', () => res.send('ok'));\n");
    expect(rule(await scan(dir), '018')).toBeUndefined();
  });

  it('reports a query rewrite and ignores a fixed destination', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'redirects\nsource: req.query.next\n');
    expect(rule(await scan(dir), '019')?.severity).toBe('medium');
    await put(dir, 'a.js', "redirects\nsource: '/in'\ndestination: '/out'\n");
    expect(rule(await scan(dir), '019')).toBeUndefined();
  });

  it('reports an open matcher and ignores a fixed matcher', async () => {
    const dir = await root();
    await put(dir, 'a.js', "matcher\n'/:path*'\n");
    expect(rule(await scan(dir), '020')).toBeDefined();
    await put(dir, 'a.js', "matcher\n'/account'\n");
    expect(rule(await scan(dir), '020')).toBeUndefined();
    await put(dir, 'a.js', "'use server'\nsearchParams\n");
    expect(rule(await scan(dir), '020')).toBeDefined();
    await put(dir, 'a.js', "'use server'\nsearchParams\norigin\n");
    expect(rule(await scan(dir), '020')).toBeUndefined();
  });

  it('reports a loader sink and ignores a literal return', async () => {
    const dir = await root();
    await put(dir, 'a.ts', 'export const loader: LoaderFunction = ({ request }) => db.query(request.url);\n');
    expect(rule(await scan(dir), '021')).toBeDefined();
    await put(dir, 'a.ts', "export const loader: LoaderFunction = () => 'ok';\n");
    expect(rule(await scan(dir), '021')).toBeUndefined();
  });

  it('reports a fastify body with no schema and ignores a schema', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'fastify.post("/in", (request) => db.query(request.body.name));\n');
    expect(rule(await scan(dir), '022')).toBeDefined();
    await put(dir, 'a.js', 'fastify.post("/in", { schema }, (request) => db.query(request.body.name));\n');
    expect(rule(await scan(dir), '022')).toBeUndefined();
  });

  it('reports graphql introspection outside tests', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'graphql\nintrospection: true\n');
    expect(rule(await scan(dir), '023')).toBeDefined();
    await put(dir, 'a.js', 'graphql\ndepthLimit\n');
    await put(dir, 'test/a.js', 'graphql\nintrospection: true\n');
    expect(rule(await scan(dir), '023')).toBeUndefined();
  });

  it('reports listen without helmet and ignores helmet', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'app.listen(3000);\n');
    expect(rule(await scan(dir), '024')).toBeDefined();
    await put(dir, 'a.js', 'app.use(helmet());\napp.listen(3000);\n');
    expect(rule(await scan(dir), '024')).toBeUndefined();
  });

  it('reports a missing body limit and ignores 100kb', async () => {
    const dir = await root();
    await put(dir, 'a.js', 'app.use(express.json());\n');
    expect(rule(await scan(dir), '026')).toBeDefined();
    await put(dir, 'a.js', "app.use(express.json({ limit: '100kb' }));\n");
    expect(rule(await scan(dir), '026')).toBeUndefined();
    await put(dir, 'a.js', 'bodyLimit: 500\n');
    expect(rule(await scan(dir), '026')).toBeDefined();
  });

  it('reports a debug route without auth', async () => {
    const dir = await root();
    await put(dir, 'a.js', "app.get('/metrics', handler);\n");
    expect(rule(await scan(dir), '027')).toBeDefined();
    await put(dir, 'a.js', 'swagger\n');
    expect(rule(await scan(dir), '027')).toBeDefined();
    await put(dir, 'a.js', 'graphql-playground\n');
    expect(rule(await scan(dir), '027')).toBeDefined();
    await put(dir, 'a.js', "app.get('/metrics', auth, handler);\n");
    expect(rule(await scan(dir), '027')).toBeUndefined();
  });
});
