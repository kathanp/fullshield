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
  type IrNode,
  type ModuleIr,
} from '../../../src/engine/ir.js';
import { queryModule } from '../../../src/engine/ir-query.js';

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

  it('lowers the statement and expression forms the module walker knows', () => {
    const source = `
      import def from './d';
      import * as ns from './n';
      export * from './all';
      type Alias = string;
      interface Box { n: number }
      declare function declared(): void;
      enum E { A }
      namespace N { export const z = 1; }
      export default function exported(cond) {
        class Child extends Base { method() { return this; } }
        let x = 0;
        const y = cond ? x : 1;
        x += y || 1;
        x++;
        while (x) { break; }
        do { continue; } while (0);
        for (let i = 0; i < 1; i++) { x = i; }
        for (const key in obj) { x = key; }
        for (const item of list) { x = item; }
        switch (x) { case 1: x = 1; break; default: x = 0; }
        try { throw new Error('e'); } catch (err) { x = err; } finally { x = 1; }
        label: { x = 1; }
        debugger;
        return;
      }
      export const named = 1;
      export function also() { return; }
    `;
    const ir = lowerSource(source, 'forms.ts');
    expect(ir.functions.length).toBeGreaterThan(1);
    expect(ir.functions.some((fn) => fn.name === 'exported')).toBe(true);
  });

  it('lowers expression forms, import shapes, and cache validators', async () => {
    const forms = `
      import './side';
      import type { T } from './types';
      import * as ns from './ns';
      export type { A } from './a';
      export * from './all';
      export * as bundled from './bundled';
      export { local as renamed, type B } from './c';
      import eq = require('./eq');
      const { read: alias, extra } = require('./util');
      const member = require('./util').read;
      const skipped = require();
      const computedReq = require(name);
      const dynamic = import('./dyn');
      function* gen(a = 1, ...rest) {
        yield;
        yield a;
        yield* other();
      }
      const arrow = (x) => x + 1;
      const seq = (1, 2);
      const meta = import.meta.url;
      class Box {
        #priv = 1;
        static { const s = 1; }
        method() { return this.#priv; }
        constructor(n = 1) { return this; }
      }
      class Child extends Base {
        m() { return super.m(); }
      }
      const tagged = tag\`a\${1}\`;
      const taggedMember = obj.tag\`b\`;
      const arr = [1, , ...rest];
      const obj = { ...rest, ['k']: 1, m() {}, 2: 2 };
      ({ a } = obj);
      [b] = arr;
      for (i = 0; i < 1; i++) {}
      for (;;) {}
      async function pull() { for await (const item of list) { item; } }
      switch (x) {}
      switch (y) { case 1: break; }
      try { z = 1; } finally { z = 2; }
      const re = /a/;
      const nil = null;
      const bit = true;
      const tmpl = \`a\${x}\`;
      const callExpr = (0, foo)(1, ...rest);
      new Ctor(1);
      ++x;
      obj.n++;
      void 0;
      typeof x;
      delete obj.n;
      !x;
      +x;
      const samePhi = flag ? kept : kept;
      const namedFn = function named() { return 1; };
      const namedAgain = function named() { return 2; };
      const anon = function () { return 3; };
      const klass = class { go() { return 1; } };
      (x as string);
      (x)!;
      (x satisfies string);
    `;
    const ir = lowerSource(forms, 'forms-extra.ts', { tsPaths: { '@app/*': ['./lib/*'] } });
    expect(ir.functions.length).toBeGreaterThan(2);
    expect(ir.imports.some((link) => link.imported === '*')).toBe(true);
    lowerSource('export default class Def {}\n', 'default-class.ts');
    lowerSource('export default 1;\n', 'default-expr.ts');
    lowerSource('export default function already() { return 1; }\n', 'default-fn.ts');
    lowerSource('with (obj) { x = 1; }\n', 'with.js');
    lowerSource('class C { constructor(private n) { this.n = n; } }\n', 'param.ts');

    const node = (partial: IrNode): IrNode => partial;
    const queried = queryModule({
      file: 'q.js',
      imports: [],
      functions: [{
        name: 'f',
        file: 'q.js',
        line: 1,
        col: 0,
        params: [],
        nodes: [
          node({ op: 'assign', file: 'q.js', line: 1, col: 0, dest: 1, name: 'req' }),
          node({ op: 'assign', file: 'q.js', line: 1, col: 0, dest: 2, name: 'req', args: [9] }),
          node({ op: 'assign', file: 'q.js', line: 1, col: 0, literal: 1, dest: 3 }),
          node({ op: 'assign', file: 'q.js', line: 1, col: 0, name: 'x' }),
          node({ op: 'property-load', file: 'q.js', line: 1, col: 0, dest: 4, name: 'query', args: [1] }),
          node({ op: 'property-load', file: 'q.js', line: 1, col: 0, name: 'query', args: [1] }),
          node({ op: 'property-load', file: 'q.js', line: 1, col: 0, dest: 5 }),
          node({ op: 'property-load', file: 'q.js', line: 1, col: 0, dest: 6, name: 'id', args: [4] }),
          node({ op: 'property-load', file: 'q.js', line: 1, col: 0, dest: 7, name: '<dynamic>', args: [4] }),
          node({ op: 'property-load', file: 'q.js', line: 1, col: 0, dest: 8, name: '*', args: [4] }),
          node({ op: 'property-store', file: 'q.js', line: 1, col: 0, args: [10, 4] }),
          node({ op: 'property-store', file: 'q.js', line: 1, col: 0, args: [10, 4] }),
          node({ op: 'property-store', file: 'q.js', line: 1, col: 0, args: [11] }),
          node({ op: 'property-store', file: 'q.js', line: 1, col: 0, args: [12, 3] }),
          node({ op: 'property-load', file: 'q.js', line: 1, col: 0, dest: 13, name: 'z', args: [10] }),
          node({ op: 'await', file: 'q.js', line: 1, col: 0 }),
          node({ op: 'phi', file: 'q.js', line: 1, col: 0, dest: 15, args: [13] }),
          node({ op: 'call', file: 'q.js', line: 1, col: 0, name: 'query', args: [13] }),
          node({ op: 'call', file: 'q.js', line: 1, col: 0, name: 'other', dest: 16, args: [13] }),
          node({ op: 'call', file: 'q.js', line: 1, col: 0, name: 'query', args: [3] }),
          node({ op: 'call', file: 'q.js', line: 1, col: 0, name: 'query' }),
          node({ op: 'return', file: 'q.js', line: 1, col: 0 }),
        ],
      }],
    });
    expect(queried.some((row) => row.sink === 'query')).toBe(true);

    const dir = await mkdtemp(join(tmpdir(), 'fullshield-ir-gap-'));
    cacheDirs.push(dir);
    const hash = irConfigHash('gap.js', {
      files: new Set(['b.js', 'a.js']),
      tsPaths: { '@app/*': ['./lib/*'] },
      packageExports: { './db': './db.js' },
    });
    expect(irConfigHash('gap.js')).not.toBe(hash);
    expect(irConfigHash('gap.js', {})).not.toBe('');
    const key = irCacheKey('gap-source', hash);
    process.env.FULLSHIELD_IR_CACHE_DIR = '';
    process.env.FULLSHIELD_EXPERIMENTAL_IR = '1';
    expect(readCachedIr(key, hash)).toBeUndefined();
    process.env.FULLSHIELD_IR_CACHE_DIR = dir;
    expect(() => readCachedIr('not-a-key', hash)).toThrow(/sha256/);
    const valid: ModuleIr = {
      file: 'gap.js',
      imports: [{
        local: 'a',
        specifier: './a',
        imported: 'a',
        mappedSpecifier: './a',
        packageName: 'pkg',
        exportTarget: './a.js',
        resolved: 'a.js',
      }],
      functions: [{
        name: 'f',
        file: 'gap.js',
        line: 1,
        col: 0,
        params: [{ name: 'p', id: 1 }],
        nodes: [{ op: 'assign', file: 'gap.js', line: 1, col: 0, dest: 1, name: 'p', args: [1], literal: null, cond: 1, object: 1 }],
      }],
    };
    const cachePath = join(dir, `${key}.json`);
    const badShapes: unknown[] = [
      { v: 2, configHash: hash, ir: valid },
      { v: 1, configHash: 1, ir: valid },
      { v: 1, configHash: hash, ir: null },
      { v: 1, configHash: hash, ir: [] },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [null], functions: [] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [{ local: 1 }], functions: [] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [{ local: 'a', specifier: 'b', imported: 'c', mappedSpecifier: 1 }], functions: [] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [{ local: 'a', specifier: 'b', imported: 'c', packageName: 1 }], functions: [] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [null] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [{ name: 1, file: 'gap.js', line: 1, col: 0, params: [], nodes: [] }] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [{ name: 'f', file: 'gap.js', line: 1.5, col: 0, params: [], nodes: [] }] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [{ name: 'f', file: 'gap.js', line: 1, col: 0, params: [{ name: 'p', id: 0 }], nodes: [] }] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [{ name: 'f', file: 'gap.js', line: 1, col: 0, params: [], nodes: [{ op: 'nope', file: 'a', line: 1, col: 0 }] }] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [{ name: 'f', file: 'gap.js', line: 1, col: 0, params: [], nodes: [{ op: 'assign', file: 1, line: 1, col: 0 }] }] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [{ name: 'f', file: 'gap.js', line: 1, col: 0, params: [], nodes: [{ op: 'assign', file: 'a', line: 1, col: 0, dest: 0 }] }] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [{ name: 'f', file: 'gap.js', line: 1, col: 0, params: [], nodes: [{ op: 'assign', file: 'a', line: 1, col: 0, name: 1 }] }] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [{ name: 'f', file: 'gap.js', line: 1, col: 0, params: [], nodes: [{ op: 'assign', file: 'a', line: 1, col: 0, args: ['x'] }] }] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: [], functions: [{ name: 'f', file: 'gap.js', line: 1, col: 0, params: [], nodes: [{ op: 'assign', file: 'a', line: 1, col: 0, literal: {} }] }] } },
      { v: 1, configHash: hash, ir: { imports: [], functions: [] } },
      { v: 1, configHash: hash, ir: { file: 'gap.js', imports: 'no', functions: [] } },
    ];
    for (const shape of badShapes) {
      mkdirSync(dir, { recursive: true });
      writeFileSync(cachePath, JSON.stringify(shape));
      expect(readCachedIr(key, hash)).toBeUndefined();
    }
    writeCachedIr(key, valid, hash);
    expect(readCachedIr(key, hash)?.file).toBe('gap.js');
    delete process.env.FULLSHIELD_EXPERIMENTAL_IR;
    writeCachedIr(key, valid, hash);
    expect(readCachedIr(key, hash)).toBeUndefined();
    delete process.env.FULLSHIELD_IR_CACHE_DIR;
  });
});
