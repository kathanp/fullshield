import { createRequire } from 'node:module';

import { currentRaspContext } from './context.js';
import { emitRaspEvent, raspEgressAllow, raspModeFor, runDecide } from './enable.js';
import { egressAllowed } from './egress.js';
import { addThreat } from './threat.js';
import { raspContext } from './middleware.js';
import { fetchUrl, urlFromHttpArgs } from './ssrf.js';
import { RASP_FAIL_OPEN, RaspBlockedError, type SinkKind } from './types.js';

export { RaspBlockedError };

const require = createRequire(import.meta.url);

const restorers: Array<() => void> = [];
const wrappedPackages = new WeakSet<object>();
let hooksLive = false;
let sqliteHookRegistered = false;

function sampleOf(sink: unknown): string {
  if (typeof sink === 'string') {return sink.slice(0, 40);}
  if (sink === null || sink === undefined) {return '';}
  return '[object]';
}

function inferPathBase(p: string): string | undefined {
  const ctx = currentRaspContext();
  if (!ctx) {return undefined;}
  for (const s of ctx.strings) {
    if (!s) {continue;}
    const idx = p.indexOf(s);
    if (idx > 0) {return p.slice(0, idx);}
  }
  return undefined;
}

function guardSink(kind: SinkKind, sink: unknown, base?: string): void {
  try {
    const ctx = currentRaspContext();
    if (ctx) {
      const decision = runDecide(kind, sink, ctx, base);
      if (decision.block && decision.ruleId) {
        emitRaspEvent({
          ruleId: decision.ruleId,
          path: ctx.path,
          ip: ctx.ip,
          sample: sampleOf(sink),
        });
        addThreat(ctx.ip, 'block');
        if (raspModeFor(ctx.path, kind) === 'block') {throw new RaspBlockedError(decision.ruleId);}
      }
    }
  } catch (err) {
    if (err instanceof RaspBlockedError) {throw err;}
    const ctx = currentRaspContext();
    emitRaspEvent({
      ruleId: RASP_FAIL_OPEN,
      path: ctx?.path ?? '/',
      ip: ctx?.ip ?? 'unknown',
      sample: 'hook-error',
    });
  }
}

function applySink<T>(kind: SinkKind, sink: unknown, base: string | undefined, original: () => T): T {
  guardSink(kind, sink, base);
  return original();
}

function patchMethod(obj: object, key: string, wrapper: (orig: (...args: never[]) => unknown) => (...args: never[]) => unknown): void {
  const record = obj as Record<string, unknown>;
  const orig = record[key];
  if (typeof orig !== 'function') {return;}
  const wrapped = wrapper(orig as (...args: never[]) => unknown);
  try {
    Object.defineProperty(wrapped, 'name', { value: (orig as { name: string }).name });
  } catch {
    // ignore
  }
  record[key] = wrapped;
  restorers.push(() => {
    record[key] = orig;
  });
}

function sqlTextFrom(sql: unknown): string {
  if (typeof sql === 'string') {return sql;}
  if (Array.isArray(sql)) {
    return sql.filter((part): part is string => typeof part === 'string').join(' ');
  }
  if (sql !== null && typeof sql === 'object') {
    const rec = sql as Record<string, unknown>;
    if (typeof rec.text === 'string') {return rec.text;}
    if (typeof rec.sql === 'string') {return rec.sql;}
    if (Array.isArray(rec.strings)) {
      return rec.strings.filter((part): part is string => typeof part === 'string').join(' ');
    }
  }
  return '';
}

function wrapSqlMethod(obj: object, key: string): void {
  patchMethod(obj, key, (orig) => {
    return function (this: unknown, sql: unknown, ...rest: unknown[]) {
      return applySink('sql', sqlTextFrom(sql), undefined, () =>
        orig.call(this, sql as never, ...(rest as never[])),
      );
    };
  });
}

function wrapNosqlWhere(obj: object, key: string): void {
  patchMethod(obj, key, (orig) => {
    return function (this: unknown, expr: unknown, ...rest: unknown[]) {
      const sink = typeof expr === 'string' ? { $where: expr } : (expr ?? {});
      return applySink('nosql', sink, undefined, () => orig.call(this, expr as never, ...(rest as never[])));
    };
  });
}

function wrapShellCommand(obj: object, key: string, shellAlways: boolean): void {
  patchMethod(obj, key, (orig) => {
    return function (this: unknown, ...args: unknown[]) {
      const opts = args[1] && typeof args[1] === 'object' ? (args[1] as { shell?: unknown }) : args[2] && typeof args[2] === 'object' ? (args[2] as { shell?: unknown }) : undefined;
      const useShell = shellAlways || opts?.shell === true;
      if (!useShell) {return orig.call(this, ...(args as never[]));}
      const cmd = typeof args[0] === 'string' ? args[0] : '';
      return applySink('shell', cmd, undefined, () => orig.call(this, ...(args as never[])));
    };
  });
}

function wrapFsPath(obj: object, key: string): void {
  patchMethod(obj, key, (orig) => {
    return function (this: unknown, pathArg: unknown, ...rest: unknown[]) {
      const p =
        typeof pathArg === 'string'
          ? pathArg
          : Buffer.isBuffer(pathArg)
            ? pathArg.toString()
            : pathArg instanceof URL
              ? pathArg.pathname
              : typeof pathArg === 'number' || typeof pathArg === 'boolean'
                ? String(pathArg)
                : '';
      return applySink('path', p, inferPathBase(p), () => orig.call(this, pathArg as never, ...(rest as never[])));
    };
  });
}

function checkEgress(url: string): void {
  const allow = raspEgressAllow();
  if (!allow || allow.length === 0) {return;}
  let host = '';
  try {
    host = new URL(url).hostname;
  } catch {
    return;
  }
  if (host && !egressAllowed(host, allow)) {
    const ctx = currentRaspContext();
    emitRaspEvent({
      ruleId: 'RASP-EGRESS-001',
      path: ctx?.path ?? '/',
      ip: ctx?.ip ?? 'unknown',
      sample: host.slice(0, 40),
    });
    if (ctx) {addThreat(ctx.ip, 'block');}
    if (raspModeFor(ctx?.path ?? '/', 'ssrf') === 'block') {throw new RaspBlockedError('RASP-EGRESS-001');}
  }
}

function wrapSsrf(obj: object, key: string, urlOf: (args: unknown[]) => string): void {
  patchMethod(obj, key, (orig) => {
    return function (this: unknown, ...args: unknown[]) {
      const url = urlOf(args);
      checkEgress(url);
      return applySink('ssrf', url, undefined, () => orig.call(this, ...(args as never[])));
    };
  });
}

const WRAP_SQLITE = Symbol.for('fullshield.rasp.wrapSqlite');
const SQLITE_WRAPPED = Symbol.for('fullshield.rasp.sqliteWrapped');

let origModuleLoad: ((request: unknown, parent: unknown, isMain: unknown) => unknown) | undefined;

function protoFrom(value: unknown): (object & Record<symbol, unknown>) | undefined {
  if (!value || typeof value !== 'object') {return undefined;}
  const proto = (value as { DatabaseSync?: { prototype?: object } }).DatabaseSync?.prototype;
  if (proto && typeof proto === 'object') {return proto as object & Record<symbol, unknown>;}
  return undefined;
}

function sqlitePrototype(hint?: unknown): (object & Record<symbol, unknown>) | undefined {
  const fromHint = protoFrom(hint);
  if (fromHint) {return fromHint;}
  const getBuiltin = (process as { getBuiltinModule?: (id: string) => unknown }).getBuiltinModule;
  if (typeof getBuiltin === 'function') {
    try {
      const fromBuiltin = protoFrom(getBuiltin.call(process, 'node:sqlite') ?? getBuiltin.call(process, 'sqlite'));
      if (fromBuiltin) {return fromBuiltin;}
    } catch {
      // not loaded
    }
  }
  if (origModuleLoad) {
    try {
      return protoFrom(origModuleLoad('node:sqlite', undefined, false));
    } catch {
      // not loaded
    }
  }
  return undefined;
}

function sqliteAlreadyLoaded(): boolean {
  const list = (process as { moduleLoadList?: string[] }).moduleLoadList;
  return Array.isArray(list) && list.some((entry) => /(?:^| )sqlite$/i.test(entry));
}

function wrapSqliteNow(hint?: unknown): void {
  try {
    const proto = sqlitePrototype(hint);
    if (!proto || proto[SQLITE_WRAPPED]) {return;}
    Object.defineProperty(proto, SQLITE_WRAPPED, { value: true, configurable: true });
    wrapSqlMethod(proto, 'exec');
    wrapSqlMethod(proto, 'prepare');
    restorers.push(() => {
      delete proto[SQLITE_WRAPPED];
    });
  } catch {
    // node:sqlite is loaded only when the app (or history/confirm) actually imports it
  }
}

function wrapBuiltins(): void {
  (globalThis as Record<symbol, unknown>)[WRAP_SQLITE] = wrapSqliteNow;

  const cp = require('node:child_process') as object;
  const cpAlias = require('child_process') as object;
  for (const mod of new Set([cp, cpAlias])) {
    wrapShellCommand(mod, 'exec', true);
    wrapShellCommand(mod, 'execSync', true);
    wrapShellCommand(mod, 'spawn', false);
    wrapShellCommand(mod, 'spawnSync', false);
    wrapShellCommand(mod, 'execFile', false);
    wrapShellCommand(mod, 'execFileSync', false);
  }

  const fsNames = [
    'readFile',
    'readFileSync',
    'writeFile',
    'writeFileSync',
    'appendFile',
    'appendFileSync',
    'open',
    'openSync',
    'createReadStream',
    'createWriteStream',
    'stat',
    'statSync',
    'lstat',
    'lstatSync',
    'access',
    'accessSync',
    'readdir',
    'readdirSync',
    'unlink',
    'unlinkSync',
    'rm',
    'rmSync',
  ];
  const fs = require('node:fs') as object;
  const fsAlias = require('fs') as object;
  for (const mod of new Set([fs, fsAlias])) {
    for (const name of fsNames) {wrapFsPath(mod, name);}
  }
  try {
    const fsp = require('node:fs/promises') as object;
    for (const name of ['readFile', 'writeFile', 'appendFile', 'open', 'stat', 'lstat', 'access', 'readdir', 'unlink', 'rm']) {
      wrapFsPath(fsp, name);
    }
  } catch {
    // ignore
  }

  const http = require('node:http') as object;
  const https = require('node:https') as object;
  wrapSsrf(http, 'request', urlFromHttpArgs);
  wrapSsrf(http, 'get', urlFromHttpArgs);
  wrapSsrf(https, 'request', urlFromHttpArgs);
  wrapSsrf(https, 'get', urlFromHttpArgs);

  if (typeof globalThis.fetch === 'function') {
    const origFetch = globalThis.fetch;
    globalThis.fetch = function (this: unknown, input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) {
      const start = fetchUrl(input);
      checkEgress(start);
      const mode = init?.redirect ?? 'follow';
      if (mode !== 'follow') {
        return applySink('ssrf', start, undefined, () => origFetch.call(this, input, init));
      }
      guardSink('ssrf', start);
      return (async () => {
        let current = start;
        let nextInput: Parameters<typeof fetch>[0] = input;
        for (let hop = 0; hop < 8; hop += 1) {
          const res = await origFetch.call(this, nextInput, { ...init, redirect: 'manual' });
          if (res.status < 300 || res.status >= 400) {return res;}
          const loc = res.headers.get('location');
          if (!loc) {return res;}
          current = new URL(loc, current).href;
          guardSink('ssrf', current);
          nextInput = current;
        }
        return origFetch.call(this, current, init);
      })();
    };
    restorers.push(() => {
      globalThis.fetch = origFetch;
    });
  }

  const vm = require('node:vm') as object;
  for (const name of ['runInNewContext', 'runInThisContext', 'runInContext', 'compileFunction']) {
    patchMethod(vm, name, (orig) => {
      return function (this: unknown, code: unknown, ...rest: unknown[]) {
        return applySink('sql', typeof code === 'string' ? code : '', undefined, () =>
          orig.call(this, code as never, ...(rest as never[])),
        );
      };
    });
  }

  const Module = require('node:module') as { _load: (...args: unknown[]) => unknown };
  origModuleLoad = Module._load.bind(Module);
  const origLoad = Module._load;
  Module._load = function (this: unknown, request: unknown, parent: unknown, isMain: unknown) {
    const exported = origLoad.call(this, request, parent, isMain);
    try {
      return wrapKnownPackage(String(request), exported);
    } catch {
      emitRaspEvent({
        ruleId: RASP_FAIL_OPEN,
        path: currentRaspContext()?.path ?? '/',
        ip: currentRaspContext()?.ip ?? 'unknown',
        sample: 'hook-error',
      });
      return exported;
    }
  };
  restorers.push(() => {
    Module._load = origLoad;
    origModuleLoad = undefined;
  });

  const registerHooks = (Module as { registerHooks?: (hooks: {
    load?: (url: string, context: unknown, nextLoad: (url: string, context: unknown) => unknown) => unknown;
  }) => void }).registerHooks;
  if (typeof registerHooks === 'function' && !sqliteHookRegistered) {
    sqliteHookRegistered = true;
    registerHooks({
      load(url, context, nextLoad) {
        const result = nextLoad(url, context);
        if (hooksLive && typeof url === 'string' && (url === 'node:sqlite' || url.startsWith('node:sqlite'))) {
          wrapSqliteNow();
        }
        return result;
      },
    });
  }

  if (sqliteAlreadyLoaded()) {wrapSqliteNow();}
}

function wrapExpressLike(exported: unknown): void {
  if (typeof exported !== 'function') {return;}
  const orig = exported as ((...args: unknown[]) => { use?: (fn: unknown) => void }) & { [k: string]: unknown };
  if (wrappedPackages.has(orig)) {return;}
  function patched(this: unknown, ...args: unknown[]) {
    const app = orig.apply(this, args);
    try {
      if (app && typeof app.use === 'function' && !(app as { __fullshieldRasp?: boolean }).__fullshieldRasp) {
        app.use(raspContext());
        (app as { __fullshieldRasp?: boolean }).__fullshieldRasp = true;
      }
    } catch {
      emitRaspEvent({
        ruleId: RASP_FAIL_OPEN,
        path: '/',
        ip: 'unknown',
        sample: 'hook-error',
      });
    }
    return app;
  }
  Object.assign(patched, orig);
  Object.setPrototypeOf(patched, orig);
  wrappedPackages.add(orig);
  // Caller replaces export; Module._load returns patched via wrapKnownPackage return
  (exported as { __fullshieldExpressPatch?: unknown }).__fullshieldExpressPatch = patched;
}

export function wrapKnownPackage(request: string, exported: unknown): unknown {
  if (exported === null || (typeof exported !== 'object' && typeof exported !== 'function')) {return exported;}
  const obj = exported;
  if (wrappedPackages.has(obj)) {return exported;}
  const name = request.replace(/^node:/, '');

  if (name === 'sqlite') {
    wrapSqliteNow(exported);
    return exported;
  }

  if (name === 'pg' || name.endsWith('/pg')) {
    const pg = exported as { Client?: { prototype: object }; Pool?: { prototype: object } };
    if (pg.Client?.prototype) {wrapSqlMethod(pg.Client.prototype, 'query');}
    if (pg.Pool?.prototype) {wrapSqlMethod(pg.Pool.prototype, 'query');}
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'mysql2' || name.endsWith('/mysql2') || name.includes('mysql2/')) {
    const mysql = exported as { Connection?: { prototype: object }; prototype?: object };
    const proto = mysql.Connection?.prototype ?? mysql.prototype;
    if (proto) {
      wrapSqlMethod(proto, 'query');
      wrapSqlMethod(proto, 'execute');
    }
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'better-sqlite3' || name.endsWith('/better-sqlite3')) {
    const proto = (exported as { prototype?: object }).prototype;
    if (proto) {
      wrapSqlMethod(proto, 'exec');
      wrapSqlMethod(proto, 'prepare');
    }
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === '@prisma/client' || name === 'prisma' || name.endsWith('/@prisma/client')) {
    const client = (exported as { PrismaClient?: { prototype: object } }).PrismaClient?.prototype;
    if (client) {
      wrapSqlMethod(client, '$queryRawUnsafe');
      wrapSqlMethod(client, '$executeRawUnsafe');
      wrapSqlMethod(client, '$queryRaw');
      wrapSqlMethod(client, '$executeRaw');
    }
    const Prisma = (exported as { Prisma?: object }).Prisma;
    if (Prisma) {wrapSqlMethod(Prisma, 'raw');}
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'sequelize' || name.endsWith('/sequelize')) {
    const rec = exported as { Sequelize?: { prototype?: object; literal?: unknown }; prototype?: object; literal?: unknown };
    const proto = rec.Sequelize?.prototype ?? rec.prototype;
    if (proto) {wrapSqlMethod(proto, 'query');}
    if (typeof rec.literal === 'function') {wrapSqlMethod(rec, 'literal');}
    if (rec.Sequelize && typeof rec.Sequelize.literal === 'function') {wrapSqlMethod(rec.Sequelize, 'literal');}
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'knex' || name.endsWith('/knex')) {
    if (typeof (exported as { raw?: unknown }).raw === 'function') {wrapSqlMethod(obj, 'raw');}
    const client = (exported as { Client?: { prototype?: object } }).Client?.prototype;
    if (client) {
      wrapSqlMethod(client, 'raw');
      wrapSqlMethod(client, 'whereRaw');
      wrapSqlMethod(client, 'orderByRaw');
      wrapSqlMethod(client, 'query');
    }
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'typeorm' || name.endsWith('/typeorm')) {
    const rec = exported as Record<string, { prototype?: object } | undefined>;
    for (const cls of ['DataSource', 'EntityManager', 'QueryRunner', 'Connection']) {
      const proto = rec[cls]?.prototype;
      if (proto) {wrapSqlMethod(proto, 'query');}
    }
    const qb = rec.SelectQueryBuilder?.prototype ?? rec.QueryBuilder?.prototype;
    if (qb) {wrapSqlMethod(qb, 'where');}
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'drizzle-orm' || name.endsWith('/drizzle-orm')) {
    const sql = (exported as { sql?: object }).sql;
    if (sql) {wrapSqlMethod(sql, 'raw');}
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'mongodb' || name.includes('mongodb')) {
    const col = (exported as { Collection?: { prototype: object } }).Collection?.prototype;
    if (col) {
      patchMethod(col, 'find', (orig) => {
        return function (this: unknown, query: unknown, ...rest: unknown[]) {
          return applySink('nosql', query ?? {}, undefined, () => orig.call(this, query as never, ...(rest as never[])));
        };
      });
    }
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'mongoose' || name.includes('mongoose')) {
    const q = (exported as { Query?: { prototype: object } }).Query?.prototype;
    if (q) {
      patchMethod(q, 'find', (orig) => {
        return function (this: unknown, query: unknown, ...rest: unknown[]) {
          return applySink('nosql', query ?? {}, undefined, () => orig.call(this, query as never, ...(rest as never[])));
        };
      });
      wrapNosqlWhere(q, '$where');
    }
    const model = (exported as { Model?: { prototype?: object } }).Model?.prototype;
    if (model) {wrapNosqlWhere(model, '$where');}
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'axios') {
    const ax = exported as { request?: unknown; get?: unknown; post?: unknown };
    const urlOf = (args: unknown[]) => {
      const a = args[0];
      if (typeof a === 'string') {return a;}
      if (a && typeof a === 'object' && 'url' in a && typeof a.url === 'string') {return a.url;}
      return '';
    };
    wrapSsrf(ax, 'request', urlOf);
    wrapSsrf(ax, 'get', urlOf);
    wrapSsrf(ax, 'post', urlOf);
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'express') {
    wrapExpressLike(exported);
    const patched = (exported as { __fullshieldExpressPatch?: unknown }).__fullshieldExpressPatch;
    if (typeof patched === 'function') {
      const resp = (exported as { response?: { redirect?: unknown } }).response;
      if (resp && typeof resp.redirect === 'function') {
        patchMethod(resp, 'redirect', (orig) => {
          return function (this: unknown, ...args: unknown[]) {
            const url = typeof args[0] === 'string' ? args[0] : typeof args[1] === 'string' ? args[1] : '';
            return applySink('ssrf', url, undefined, () => orig.call(this, ...(args as never[])));
          };
        });
      }
      wrappedPackages.add(obj);
      return patched;
    }
  }
  return exported;
}

export function installHooks(): void {
  hooksLive = true;
  wrapBuiltins();
}

export function restoreHooks(): void {
  hooksLive = false;
  delete (globalThis as Record<symbol, unknown>)[WRAP_SQLITE];
  while (restorers.length > 0) {restorers.pop()?.();}
}

