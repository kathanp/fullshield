import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import diagnosticsChannel from 'node:diagnostics_channel';
import { afterEach, describe, expect, it } from 'vitest';

import { contextFromRequest, enterRaspContext } from '../../../src/runtime/rasp/context.js';
import { clearDnsPins, setDnsPinNow } from '../../../src/runtime/rasp/dns-pin.js';
import { clearRaspEvents, disableRasp, enableRasp, getRaspEvents } from '../../../src/runtime/rasp/enable.js';
import { wrapKnownPackage } from '../../../src/runtime/rasp/hooks.js';
import { decideSink, scoreCorpus } from '../../../src/runtime/rasp/decide.js';
import { hostIsBlocked, setSsrfLookup } from '../../../src/runtime/rasp/ssrf.js';
import { RaspBlockedError } from '../../../src/runtime/rasp/types.js';

const benign = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../../fixtures/rasp/benign-corpus.json'), 'utf8'),
) as { cases: Array<Record<string, unknown>> };

const attacks = ['$gt', '$ne', '$where', '$regex', '$in', '$nin', '$or', '$and', '$nor', '$expr'] as const;
const benignFilters = ['ada', 'bob', 'cy', 'dee', 'ed', 'fay', 'gus', 'hal', 'ivy', 'jo'];

afterEach(() => {
  disableRasp();
  setSsrfLookup(undefined);
  setDnsPinNow(undefined);
  clearDnsPins();
});

function collection() {
  const proto = {
    find(q: unknown) { return q; },
    findOne(q: unknown) { return q; },
    aggregate(q: unknown) { return q; },
    updateOne(q: unknown) { return q; },
    updateMany(q: unknown) { return q; },
    deleteOne(q: unknown) { return q; },
    deleteMany(q: unknown) { return q; },
    countDocuments(q: unknown) { return q; },
  };
  return proto;
}

describe('phase 71 rasp sink coverage', () => {
  it('hooks mongodb and mongoose filter methods and leaves benign queries alone', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const mongo = { Collection: { prototype: collection() } };
    const mongoose = {
      Query: { prototype: collection() },
      Model: { aggregate(q: unknown) { return q; }, prototype: { $where(q: unknown) { return q; } } },
    };
    wrapKnownPackage('mongodb', mongo);
    wrapKnownPackage('mongoose', mongoose);
    const attack = { $gt: '' };
    const ctx = contextFromRequest({ body: attack });
    expect(() => enterRaspContext(ctx, () => mongo.Collection.prototype.findOne(attack))).toThrow(RaspBlockedError);
    expect(() => enterRaspContext(ctx, () => mongo.Collection.prototype.aggregate([attack]))).toThrow(RaspBlockedError);
    expect(() => enterRaspContext(ctx, () => mongoose.Query.prototype.updateOne(attack))).toThrow(RaspBlockedError);
    expect(() => enterRaspContext(ctx, () => mongoose.Model.aggregate([attack]))).toThrow(RaspBlockedError);
    const plain = { name: 'ada' };
    expect(enterRaspContext(contextFromRequest({ body: plain }), () => mongo.Collection.prototype.findOne(plain))).toEqual(plain);
    for (const op of attacks) {
      const row = { [op]: 1 };
      expect(decideSink('nosql', row, contextFromRequest({ body: row })).block).toBe(true);
    }
    for (const name of benignFilters) {
      const row = { name };
      expect(decideSink('nosql', row, contextFromRequest({ body: row })).block).toBe(false);
    }
  });

  it('hooks axios verbs, axios.create, undici request, and the undici diagnostics channel', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const axios = {
      request(url: string) { return url; },
      get(url: string) { return url; },
      post(url: string) { return url; },
      put(url: string) { return url; },
      patch(url: string) { return url; },
      delete(url: string) { return url; },
      head(url: string) { return url; },
      options(url: string) { return url; },
      create() {
        return { get(url: string) { return url; } };
      },
    };
    const undici = {
      request(url: string) { return url; },
      Dispatcher: { prototype: { request(url: string) { return url; } } },
      Agent: { prototype: { request(url: string) { return url; } } },
    };
    wrapKnownPackage('axios', axios);
    wrapKnownPackage('undici', undici);
    const ctx = contextFromRequest({ query: { url: 'http://127.0.0.1/admin' } });
    expect(() => enterRaspContext(ctx, () => axios.put('http://127.0.0.1/admin'))).toThrow(RaspBlockedError);
    expect(() => enterRaspContext(ctx, () => axios.create().get('http://127.0.0.1/admin'))).toThrow(RaspBlockedError);
    expect(() => enterRaspContext(ctx, () => undici.request('http://127.0.0.1/admin'))).toThrow(RaspBlockedError);
    expect(() => enterRaspContext(ctx, () => undici.Dispatcher.prototype.request('http://127.0.0.1/admin'))).toThrow(RaspBlockedError);
    expect(() => enterRaspContext(ctx, () => undici.Agent.prototype.request('http://127.0.0.1/admin'))).toThrow(RaspBlockedError);
    expect(enterRaspContext(ctx, () => axios.get('https://example.invalid/ok'))).toBe('https://example.invalid/ok');
    clearRaspEvents();
    enterRaspContext(ctx, () => {
      diagnosticsChannel.channel('undici:request:create').publish({ url: 'http://127.0.0.1/admin' });
    });
    expect(getRaspEvents().some((event) => event.ruleId === 'RASP-SSRF-001')).toBe(true);
    const privateUrls = [
      'http://127.0.0.1/a', 'http://127.0.0.2/b', 'http://10.0.0.1/', 'http://10.1.1.1/', 'http://192.168.0.1/',
      'http://172.16.0.1/', 'http://169.254.169.254/', 'http://localhost/x', 'http://0.0.0.0/', 'http://[::1]/',
    ];
    for (const url of privateUrls) {
      expect(decideSink('ssrf', url, contextFromRequest({ query: { url } })).block).toBe(true);
    }
    for (let i = 0; i < 10; i += 1) {
      const url = `https://ok-${i}.example.invalid/item`;
      expect(decideSink('ssrf', url, contextFromRequest({ query: { url } })).block).toBe(false);
    }
  });

  it('keeps the benign rasp corpus at zero blocked', () => {
    expect(scoreCorpus(benign.cases).blocked).toBe(0);
  });
});

describe('phase 72 rasp dns pin', () => {
  it('blocks a later private address for the same host and allows a public address after the ttl', () => {
    const answers = [['8.8.8.8'], ['127.0.0.1'], ['1.1.1.1']];
    setSsrfLookup(() => answers.shift() ?? ['1.1.1.1']);
    let now = 1_000;
    setDnsPinNow(() => now);
    const ctx = contextFromRequest({ path: '/out', ip: '203.0.113.9' });
    enterRaspContext(ctx, () => {
      expect(hostIsBlocked('rebind.example')).toBe(false);
      expect(hostIsBlocked('rebind.example')).toBe(true);
    });
    now = 70_000;
    enterRaspContext(ctx, () => {
      expect(hostIsBlocked('rebind.example')).toBe(false);
    });
  });
});

describe('phase 97 rasp template source', () => {
  it('blocks a request string used as the template and allows a fixed template', () => {
    enableRasp({ experimental: true, mode: 'block' });
    const ejs = { render(src: string) { return src; } };
    const pug = { render(src: string) { return src; } };
    const nunjucks = { renderString(src: string) { return src; } };
    wrapKnownPackage('ejs', ejs);
    wrapKnownPackage('pug', pug);
    wrapKnownPackage('nunjucks', nunjucks);
    const tpl = '<%= user %>';
    const ctx = contextFromRequest({ body: { tpl } });
    expect(() => enterRaspContext(ctx, () => ejs.render(tpl))).toThrow(RaspBlockedError);
    expect(() => enterRaspContext(ctx, () => pug.render(tpl))).toThrow(RaspBlockedError);
    expect(() => enterRaspContext(ctx, () => nunjucks.renderString(tpl))).toThrow(RaspBlockedError);
    expect(enterRaspContext(ctx, () => ejs.render('Hello <%= name %>'))).toBe('Hello <%= name %>');
    expect(decideSink('ssti', tpl, ctx).ruleId).toBe('RASP-SSTI-001');
  });
});
