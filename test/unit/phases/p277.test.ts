import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p277.js';

const query = 'function run() { db.query(req.query.id); }\n';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 277', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeReflect(query).findings).toEqual([]);
  });

  it('reports a request query and ignores a literal', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeReflect(query).findings.some((row) => row.sinkClass === 'sqli')).toBe(true);
    expect(phase.analyzeReflect('function run() { db.query("1"); }').findings).toEqual([]);
  });

  it('follows reflect, proxies, and defineProperty', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeReflect(':::').findings).toEqual([]);
    const source = [
      'with (obj) {}',
      'const trick = Function.prototype.toString;',
      'function run() {',
      '  const box = { a: req.query.id, m() {}, ["k"]: 1 };',
      '  const forwarded = new Proxy(box, { get(target) { return target.a; } });',
      '  const opaque = new Proxy(box, {});',
      '  const loose = new Proxy(...args);',
      '  Reflect.set(box, "b", req.query.id);',
      '  Reflect.set(box);',
      '  Object.defineProperty(box, "c", { get() { return req.query.id; } });',
      '  Object.defineProperty(box, "d", { get: () => req.query.id });',
      '  x = req.query.id;',
      '  db.query(box.a);',
      '  db.query(box.missing);',
      '  db.query(Reflect.get(box, "b"));',
      '  db.query(Reflect.get(box, key));',
      '  db.query(Reflect.get(missing, "a"));',
      '  db.query(Reflect.apply(fn, null, [req.query.id, null]));',
      '  db.query(Reflect.apply(fn, null, req.query.id));',
      '  db.query(x + "z");',
      '  db.query(...args);',
      '  { db.query(forwarded.a); }',
      '}',
    ].join('\n');
    expect(phase.analyzeReflect(source).findings.length).toBeGreaterThan(0);
    expect(phase.analyzeReflect(source, { mode: 'sound' }).events.some((event) => event.kind === 'proxy')).toBe(true);
    delete process.env[phase.FLAG];
  });
});
