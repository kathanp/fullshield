import diagnosticsChannel from 'node:diagnostics_channel';

import { afterEach, describe, expect, it } from 'vitest';

import { enterRaspContext } from '../../../src/runtime/rasp/context.js';
import { clearRaspEvents, disableRasp, enableRasp, getRaspEvents } from '../../../src/runtime/rasp/enable.js';
import { wrapKnownPackage } from '../../../src/runtime/rasp/hooks.js';
import { RaspBlockedError, type RaspRequestContext } from '../../../src/runtime/rasp/types.js';

const NOSQL_ATTACKS = ['$gt', '$ne', '$in', '$nin', '$or', '$and', '$regex', '$expr', '$elemMatch', '$where'].map(
  (op) => ({ [op]: 'x' }),
);
const NOSQL_BENIGN = Array.from({ length: 10 }, (_, i) => ({ name: `ada-${i}`, age: i }));
const SSRF_ATTACKS = [
  '127.0.0.1',
  '10.0.0.8',
  '192.168.1.9',
  '172.16.0.4',
  '169.254.169.254',
  'localhost',
  '0.0.0.0',
  '127.0.0.2',
  '10.1.2.3',
  '192.168.0.2',
];
const SSRF_BENIGN = [
  '1.1.1.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
  '1.0.0.1',
  '208.67.222.222',
  '208.67.220.220',
  '94.140.14.14',
  '76.76.2.0',
  '185.228.168.9',
];

afterEach(() => {
  disableRasp();
});

describe('phase 71 rasp sink coverage', () => {
  it('blocks operator filters on mongodb methods and allows plain filters', () => {
    const methods = ['findOne', 'aggregate', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'countDocuments'];
    const proto: Record<string, (query: unknown) => unknown> = {};
    for (const key of methods) proto[key] = (query) => query;
    wrapKnownPackage('mongodb', { Collection: { prototype: proto } });
    expect(countBlocked(NOSQL_ATTACKS, (payload) => proto.findOne!(payload), nosqlCtx)).toBe(10);
    expect(countBlocked(NOSQL_BENIGN, (payload) => proto.findOne!(payload), nosqlCtx)).toBe(0);
    for (const key of methods) {
      const attack = NOSQL_ATTACKS[0]!;
      expect(() => run(nosqlCtx(attack), () => proto[key]!(attack))).toThrow(RaspBlockedError);
      expect(run(nosqlCtx(NOSQL_BENIGN[0]!), () => proto[key]!(NOSQL_BENIGN[0]!))).toEqual(NOSQL_BENIGN[0]);
    }
  });

  it('blocks operator filters on mongoose query methods and Model.aggregate', () => {
    const methods = ['findOne', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'countDocuments'];
    const proto: Record<string, (query: unknown) => unknown> = {};
    for (const key of methods) proto[key] = (query) => query;
    function Model(this: unknown) {
      return this;
    }
    Model.aggregate = (pipeline: unknown) => pipeline;
    wrapKnownPackage('mongoose', { Query: { prototype: proto }, Model });
    expect(countBlocked(NOSQL_ATTACKS, (payload) => proto.findOne!(payload), nosqlCtx)).toBe(10);
    expect(countBlocked(NOSQL_BENIGN, (payload) => proto.findOne!(payload), nosqlCtx)).toBe(0);
    const attack = NOSQL_ATTACKS[0]!;
    expect(() => run(nosqlCtx(attack), () => Model.aggregate(attack))).toThrow(RaspBlockedError);
    expect(run(nosqlCtx(NOSQL_BENIGN[0]!), () => Model.aggregate(NOSQL_BENIGN[0]!))).toEqual(NOSQL_BENIGN[0]);
  });

  it('checks axios put/patch/delete/head/options and clients from axios.create()', () => {
    const client = httpClient();
    const axios = { ...httpClient(), create: () => client };
    wrapKnownPackage('axios', axios);
    const created = axios.create();
    const put = created.put;
    if (put === undefined) throw new Error('axios client is missing put');
    expect(countBlocked(SSRF_ATTACKS, (host) => put(`http://${host}/a`), ssrfCtx)).toBe(10);
    expect(countBlocked(SSRF_BENIGN, (host) => put(`http://${host}/a`), ssrfCtx)).toBe(0);
    for (const key of ['patch', 'delete', 'head', 'options'] as const) {
      const method = created[key];
      if (method === undefined) throw new Error(`axios client is missing ${key}`);
      expect(() => run(ssrfCtx('127.0.0.1'), () => method('http://127.0.0.1/a'))).toThrow(RaspBlockedError);
      expect(run(ssrfCtx('1.1.1.1'), () => method('http://1.1.1.1/a'))).toBe('http://1.1.1.1/a');
    }
  });

  it('checks undici.request and Dispatcher and Agent request', () => {
    const request = (url: string) => url;
    const Dispatcher = { prototype: { request } };
    const Agent = { prototype: { request: (url: string) => url } };
    const undici = { request: (url: string) => url, Dispatcher, Agent };
    wrapKnownPackage('undici', undici);
    expect(countBlocked(SSRF_ATTACKS, (host) => undici.request(`http://${host}/a`), ssrfCtx)).toBe(10);
    expect(countBlocked(SSRF_BENIGN, (host) => undici.request(`http://${host}/a`), ssrfCtx)).toBe(0);
    expect(() => run(ssrfCtx('127.0.0.1'), () => Dispatcher.prototype.request('http://127.0.0.1/a'))).toThrow(
      RaspBlockedError,
    );
    expect(() => run(ssrfCtx('10.0.0.8'), () => Agent.prototype.request('http://10.0.0.8/a'))).toThrow(RaspBlockedError);
    expect(run(ssrfCtx('8.8.8.8'), () => Agent.prototype.request('http://8.8.8.8/a'))).toBe('http://8.8.8.8/a');
  });

  it('uses the undici diagnostics channel as a second SSRF signal and fails open', () => {
    enableRasp({ experimental: true, mode: 'block' });
    expect(wrapKnownPackage('mongodb', {})).toEqual({});
    clearRaspEvents();
    for (const host of SSRF_ATTACKS) run(ssrfCtx(host), () => publishUndici(`http://${host}/a`));
    expect(getRaspEvents().filter((event) => event.ruleId === 'RASP-SSRF-001')).toHaveLength(10);
    clearRaspEvents();
    for (const host of SSRF_BENIGN) run(ssrfCtx(host), () => publishUndici(`http://${host}/a`));
    expect(getRaspEvents().filter((event) => event.ruleId === 'RASP-SSRF-001')).toHaveLength(0);
    expect(() =>
      run(ssrfCtx('127.0.0.1'), () => {
        diagnosticsChannel.channel('undici:request:create').publish({ not: 'a request' });
      }),
    ).not.toThrow();
  });
});

function httpClient(): Record<string, (url: string) => string> {
  const send = (url: string) => url;
  return { request: send, get: send, post: send, put: send, patch: send, delete: send, head: send, options: send };
}

function nosqlCtx(payload: unknown): RaspRequestContext {
  return { path: '/', ip: 'test', strings: [], objects: [payload] };
}

function ssrfCtx(host: string): RaspRequestContext {
  return { path: '/', ip: 'test', strings: [host], objects: [] };
}

function run<T>(ctx: RaspRequestContext, fn: () => T): T {
  enableRasp({ experimental: true, mode: 'block' });
  return enterRaspContext(ctx, fn);
}

function countBlocked<T>(cases: readonly T[], call: (value: T) => unknown, ctxFor: (value: T) => RaspRequestContext): number {
  let blocked = 0;
  for (const value of cases) {
    try {
      run(ctxFor(value), () => call(value));
    } catch (err) {
      if (err instanceof RaspBlockedError) blocked += 1;
      else throw err;
    }
  }
  return blocked;
}

function publishUndici(url: string): void {
  const parsed = new URL(url);
  diagnosticsChannel.channel('undici:request:create').publish({
    request: { origin: parsed.origin, path: `${parsed.pathname}${parsed.search}` },
  });
}
