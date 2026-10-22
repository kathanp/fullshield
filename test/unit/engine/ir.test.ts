import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import {
  irCacheKey,
  irConfigHash,
  irEnabled,
  lowerSource,
  lowerSourceCached,
  readCachedIr,
  runIrQuery,
  writeCachedIr,
  type FunctionIr,
  type ModuleIr,
} from '../../../src/engine/ir.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const cacheDirs: string[] = [];

const ASSIGN_AND_CALL = `function f() {
  const x = 1;
  foo(x);
}

function h() {
  const box = {};
  box.v = 1;
  foo(box);
}
`;

const AWAIT_AND_BRANCH = `async function g(cond) {
  let x = 0;
  const y = await fetch(cond);
  if (cond) {
    x = y;
  } else {
    x = 1;
  }
  return x;
}
`;

const FLOW = `function handler(req) {
  const x = req.query.x;
  db.query(x);
}
`;

const LITERAL_SINK = `function handler() {
  const x = 'safe';
  db.query(x);
}
`;

function functionNamed(ir: ModuleIr, name: string): FunctionIr {
  const fn = ir.functions.find((item) => item.name === name);
  if (fn === undefined) {
    throw new Error(`missing function ${name}`);
  }
  return fn;
}

describe('phase 251 IR', () => {
  afterEach(async () => {
    await Promise.all(cacheDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('lowers an assignment and a call with stable SSA ids', () => {
    const first = lowerSource(ASSIGN_AND_CALL, 'inline.js');
    const second = lowerSource(ASSIGN_AND_CALL, 'inline.js');
    expect(second).toEqual(first);

    const fn = functionNamed(first, 'f');
    const assign = fn.nodes.find((node) => node.op === 'assign' && node.name === 'x');
    const call = fn.nodes.find((node) => node.op === 'call' && node.name === 'foo');
    expect(assign).toMatchObject({ op: 'assign', name: 'x', literal: 1, file: 'inline.js', line: 2 });
    expect(call).toMatchObject({ op: 'call', name: 'foo', file: 'inline.js', line: 3 });
    expect(call?.args).toEqual([assign?.dest]);
    expect(assign?.dest).toBe(1);

    const stored = functionNamed(first, 'h');
    expect(stored.nodes.some((node) => node.op === 'property-store' && node.name === 'v')).toBe(true);
    expect(stored.nodes[0]?.dest).toBe(1);

    for (const item of first.functions) {
      const dests = item.nodes.flatMap((node) => (node.dest === undefined ? [] : [node.dest]));
      expect(new Set(dests).size).toBe(dests.length);
      for (const node of item.nodes) {
        expect(node.file).toBe('inline.js');
        expect(Number.isInteger(node.line)).toBe(true);
        expect(Number.isInteger(node.col)).toBe(true);
        expect(node.line).toBeGreaterThan(0);
      }
    }
  });

  it('represents await, branch, and phi', () => {
    const ir = lowerSource(AWAIT_AND_BRANCH, 'async.js');
    const fn = functionNamed(ir, 'g');
    const cond = fn.params.find((param) => param.name === 'cond');
    const branch = fn.nodes.find((node) => node.op === 'branch');
    const phi = fn.nodes.find((node) => node.op === 'phi' && node.name === 'x');
    expect(fn.nodes.some((node) => node.op === 'await')).toBe(true);
    expect(fn.nodes.some((node) => node.op === 'call' && node.name === 'fetch')).toBe(true);
    expect(fn.nodes.some((node) => node.op === 'return')).toBe(true);
    expect(branch).toMatchObject({ op: 'branch', file: 'async.js', line: 4, col: 2, cond: cond?.id });
    expect(phi?.args).toHaveLength(2);
    expect(phi).toMatchObject({ file: 'async.js', line: 4, col: 2 });
    expect(lowerSource(AWAIT_AND_BRANCH, 'async.js')).toEqual(ir);
  });

  it('discards a corrupt cache entry and ignores the cache when the flag is off', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-ir-'));
    cacheDirs.push(dir);
    const source = 'function f() { return 1; }\n';
    const file = 'a.js';
    const hash = irConfigHash(file);
    const key = irCacheKey(source, hash);
    const cachePath = join(dir, `${key}.json`);
    process.env.FULLSHIELD_IR_CACHE_DIR = dir;

    expect(irEnabled()).toBe(false);
    expect(lowerSourceCached(source, file)).toEqual(lowerSource(source, file));
    expect(existsSync(cachePath)).toBe(false);

    process.env.FULLSHIELD_EXPERIMENTAL_IR = '1';
    mkdirSync(dir, { recursive: true });
    writeFileSync(cachePath, '{');
    expect(readCachedIr(key, hash)).toBeUndefined();
    expect(existsSync(cachePath)).toBe(false);

    writeFileSync(cachePath, JSON.stringify({ v: 1, configHash: hash, ir: { file: 1 } }));
    expect(readCachedIr(key, hash)).toBeUndefined();
    expect(existsSync(cachePath)).toBe(false);

    const rebuilt = lowerSourceCached(source, file);
    expect(rebuilt).toEqual(lowerSource(source, file));
    const stored: unknown = JSON.parse(readFileSync(cachePath, 'utf8'));
    expect(typeof stored === 'object' && stored !== null && 'v' in stored && stored.v).toBe(1);

    const poison: ModuleIr = {
      file,
      imports: [],
      functions: [{ name: 'poison', file, line: 1, col: 0, params: [], nodes: [] }],
    };
    writeCachedIr(key, poison, hash);
    expect(readCachedIr(key, hash)?.functions[0]?.name).toBe('poison');
    writeFileSync(
      cachePath,
      JSON.stringify({ v: 1, configHash: 'not-the-hash', ir: poison }),
    );
    expect(readCachedIr(key, hash)).toBeUndefined();
    expect(existsSync(cachePath)).toBe(false);

    writeCachedIr(key, poison, hash);
    delete process.env.FULLSHIELD_EXPERIMENTAL_IR;
    const ignored = lowerSourceCached(source, file);
    expect(ignored.functions.some((fn) => fn.name === 'poison')).toBe(false);
    expect(ignored).toEqual(lowerSource(source, file));
    expect(existsSync(cachePath)).toBe(true);
  });

  it('is not imported by the sast scan path', () => {
    const files = [
      'src/modules/sast/index.ts',
      'src/modules/sast/engine.ts',
      'src/core/engine.ts',
      'src/index.ts',
      'src/cli/program.ts',
    ];
    expect(irEnabled()).toBe(false);
    for (const rel of files) {
      const text = readFileSync(join(root, rel), 'utf8');
      expect(text.includes('engine/ir'), rel).toBe(false);
    }
    expect(runIrQuery(FLOW, 'handler.js')).toEqual([]);
  });

  it('reports req.query.x flowing to db.query when the flag is on', () => {
    process.env.FULLSHIELD_EXPERIMENTAL_IR = '1';
    expect(runIrQuery(FLOW, 'handler.js')).toEqual([
      { file: 'handler.js', line: 3, col: 2, sink: 'query', source: 'req.query.x' },
    ]);
    expect(runIrQuery('function handler(req) {\n  db.query(req.query.x);\n}\n', 'direct.js')).toEqual([
      { file: 'direct.js', line: 2, col: 2, sink: 'query', source: 'req.query.x' },
    ]);
    expect(
      runIrQuery('function handler(req) {\n  db.query("SELECT " + req.query.x);\n}\n', 'concat.js'),
    ).toEqual([{ file: 'concat.js', line: 2, col: 2, sink: 'query', source: 'req.query.x' }]);
    expect(
      runIrQuery('async function handler(req) {\n  const x = await req.query.x;\n  db.query(x);\n}\n', 'await.js'),
    ).toEqual([{ file: 'await.js', line: 3, col: 2, sink: 'query', source: 'req.query.x' }]);
    expect(runIrQuery(`function handler(req, cond) {
  let x = "safe";
  if (cond) {
    x = req.query.x;
  } else {
    x = "nope";
  }
  db.query(x);
}
`, 'phi.js')).toEqual([{ file: 'phi.js', line: 8, col: 2, sink: 'query', source: 'req.query.x' }]);
    expect(runIrQuery(`function handler(req) {
  let x = "safe";
  while (cond) {
    x = req.query.x;
  }
  db.query(x);
}
`, 'loop.js')).toEqual([{ file: 'loop.js', line: 6, col: 2, sink: 'query', source: 'req.query.x' }]);
  });

  it('does not report a literal flowing to db.query', () => {
    process.env.FULLSHIELD_EXPERIMENTAL_IR = '1';
    expect(runIrQuery(LITERAL_SINK, 'literal.js')).toEqual([]);
    expect(runIrQuery('function handler() {\n  db.query("literal");\n}\n', 'direct-literal.js')).toEqual([]);
    expect(
      runIrQuery(
        'function handler(req) {\n  const x = req.query.x;\n  const y = "safe";\n  db.query(y);\n}\n',
        'split.js',
      ),
    ).toEqual([]);
    expect(
      runIrQuery('function handler(cond) {\n  let x = "a";\n  if (cond) { x = "b"; } else { x = "c"; }\n  db.query(x);\n}\n', 'phi.js'),
    ).toEqual([]);
  });

  it('links import specifiers to local bindings', () => {
    const source = [
      "import { query } from './db.js';",
      "import pkg from 'left-pad';",
      "import mapped from '@app/db';",
      "import sub from 'left-pad/db';",
      "const util = require('./util.js');",
      'export { read } from "./extra.js";',
    ].join('\n');
    const ir = lowerSource(source, 'src/app.js', {
      files: new Set(['src/app.js', 'src/db.js', 'src/util.js']),
      tsPaths: { '@app/*': ['./lib/*'] },
      packageExports: { './db': './db.js' },
    });
    const byLocal = new Map(ir.imports.map((link) => [link.local, link]));
    expect(byLocal.get('query')).toMatchObject({
      local: 'query',
      specifier: './db.js',
      imported: 'query',
      resolved: 'src/db.js#query',
    });
    expect(byLocal.get('pkg')).toMatchObject({
      local: 'pkg',
      specifier: 'left-pad',
      imported: 'default',
      packageName: 'left-pad',
    });
    expect(byLocal.get('mapped')).toMatchObject({
      specifier: '@app/db',
      imported: 'default',
      packageName: '@app/db',
      mappedSpecifier: './lib/db',
    });
    expect(byLocal.get('sub')).toMatchObject({
      specifier: 'left-pad/db',
      packageName: 'left-pad',
      exportTarget: './db.js',
    });
    expect(byLocal.get('util')).toMatchObject({
      specifier: './util.js',
      resolved: 'src/util.js',
    });
    expect(byLocal.get('read')).toMatchObject({
      specifier: './extra.js',
      imported: 'read',
    });
    expect(byLocal.get('read')?.resolved).toBeUndefined();
  });
});
