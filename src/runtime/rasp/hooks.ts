import { createRequire } from 'node:module';

import { currentRaspContext } from './context.js';
import { emitRaspEvent, raspMode, runDecide } from './enable.js';
import { raspContext } from './middleware.js';
import { fetchUrl, urlFromHttpArgs } from './ssrf.js';
import { RASP_FAIL_OPEN, RaspBlockedError, type SinkKind } from './types.js';

export { RaspBlockedError };

const require = createRequire(import.meta.url);

const restorers: Array<() => void> = [];
const wrappedPackages = new WeakSet<object>();

function sampleOf(sink: unknown): string {
  if (typeof sink === 'string') return sink.slice(0, 40);
  if (sink === null || sink === undefined) return '';
  return '[object]';
}

function inferPathBase(p: string): string | undefined {
  const ctx = currentRaspContext();
  if (!ctx) return undefined;
  for (const s of ctx.strings) {
    if (!s) continue;
    const idx = p.indexOf(s);
    if (idx > 0) return p.slice(0, idx);
  }
  return undefined;
}

function applySink<T>(kind: SinkKind, sink: unknown, base: string | undefined, original: () => T): T {
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
        if (raspMode() === 'block') throw new RaspBlockedError(decision.ruleId);
      }
    }
  } catch (err) {
    if (err instanceof RaspBlockedError) throw err;
    const ctx = currentRaspContext();
    emitRaspEvent({
      ruleId: RASP_FAIL_OPEN,
      path: ctx?.path ?? '/',
      ip: ctx?.ip ?? 'unknown',
      sample: 'hook-error',
    });
  }
  return original();
}

function patchMethod(obj: object, key: string, wrapper: (orig: (...args: never[]) => unknown) => (...args: never[]) => unknown): void {
  const record = obj as Record<string, unknown>;
  const orig = record[key];
  if (typeof orig !== 'function') return;
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

function wrapSqlMethod(obj: object, key: string): void {
  patchMethod(obj, key, (orig) => {
    return function (this: unknown, sql: unknown, ...rest: unknown[]) {
      const text =
        typeof sql === 'string'
          ? sql
          : sql && typeof sql === 'object' && 'text' in sql && typeof sql.text === 'string'
            ? sql.text
            : '';
      return applySink('sql', text, undefined, () => orig.call(this, sql as never, ...(rest as never[])));
    };
  });
}

function wrapShellCommand(obj: object, key: string, shellAlways: boolean): void {
  patchMethod(obj, key, (orig) => {
    return function (this: unknown, ...args: unknown[]) {
      const opts = args[1] && typeof args[1] === 'object' ? (args[1] as { shell?: unknown }) : args[2] && typeof args[2] === 'object' ? (args[2] as { shell?: unknown }) : undefined;
      const useShell = shellAlways || opts?.shell === true;
      if (!useShell) return orig.call(this, ...(args as never[]));
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

function wrapSsrf(obj: object, key: string, urlOf: (args: unknown[]) => string): void {
  patchMethod(obj, key, (orig) => {
    return function (this: unknown, ...args: unknown[]) {
      return applySink('ssrf', urlOf(args), undefined, () => orig.call(this, ...(args as never[])));
    };
  });
}

function wrapBuiltins(): void {
  try {
    const sqlite = require('node:sqlite') as { DatabaseSync?: { prototype: object } };
    if (sqlite.DatabaseSync?.prototype) {
      wrapSqlMethod(sqlite.DatabaseSync.prototype, 'exec');
      wrapSqlMethod(sqlite.DatabaseSync.prototype, 'prepare');
    }
  } catch {
    // node:sqlite is optional on older Node
  }

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
    for (const name of fsNames) wrapFsPath(mod, name);
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
      return applySink('ssrf', fetchUrl(input), undefined, () => origFetch.call(this, input, init));
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
  });
}

function wrapExpressLike(exported: unknown): void {
  if (typeof exported !== 'function') return;
  const orig = exported as ((...args: unknown[]) => { use?: (fn: unknown) => void }) & { [k: string]: unknown };
  if (wrappedPackages.has(orig)) return;
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
  if (exported === null || (typeof exported !== 'object' && typeof exported !== 'function')) return exported;
  const obj = exported;
  if (wrappedPackages.has(obj)) return exported;
  const name = request.replace(/^node:/, '');

  if (name === 'pg' || name.endsWith('/pg')) {
    const pg = exported as { Client?: { prototype: object }; Pool?: { prototype: object } };
    if (pg.Client?.prototype) wrapSqlMethod(pg.Client.prototype, 'query');
    if (pg.Pool?.prototype) wrapSqlMethod(pg.Pool.prototype, 'query');
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'mysql2' || name.endsWith('/mysql2') || name.includes('mysql2/')) {
    const proto = (exported as { Connection?: { prototype: object } }).Connection?.prototype;
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
    }
    wrappedPackages.add(obj);
    return exported;
  }
  if (name === 'axios') {
    const ax = exported as { request?: unknown; get?: unknown; post?: unknown };
    const urlOf = (args: unknown[]) => {
      const a = args[0];
      if (typeof a === 'string') return a;
      if (a && typeof a === 'object' && 'url' in a && typeof a.url === 'string') return a.url;
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
  wrapBuiltins();
}

export function restoreHooks(): void {
  while (restorers.length > 0) restorers.pop()?.();
}

