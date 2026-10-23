import { afterEach, describe, expect, it } from 'vitest';

import { ASYNC_FLAG, asyncEnabled, asyncFindings } from '../../../src/engine/asyncflow.js';

afterEach(() => {
  delete process.env[ASYNC_FLAG];
});

describe('phase 254 async flow', () => {
  it('is off unless the flag is set', () => {
    expect(asyncEnabled()).toBe(false);
    expect(asyncFindings('const y = await load(req.query.x);\ndb.query(y);')).toEqual([]);
  });

  it('follows await, then, matching events, streams, and timers', () => {
    process.env[ASYNC_FLAG] = '1';
    expect(asyncFindings('async function f(){\nconst y = await load(req.query.x);\ndb.query(y);\n}')).toHaveLength(1);
    expect(asyncFindings('load(req.query.x).then(y => db.query(y));')).toHaveLength(1);
    const same = [
      'bus.on("data", (x) => { db.query(x); });',
      'bus.emit("data", req.query.x);',
    ].join('\n');
    expect(asyncFindings(same)).toHaveLength(1);
    expect(asyncFindings('pipeline(req, (chunk) => { db.query(chunk); });')).toHaveLength(1);
    expect(asyncFindings('const x = req.query.x;\nsetImmediate(() => { db.query(x); });')).toHaveLength(1);
  });

  it('does not cross different event names or an unresolved emitter', () => {
    process.env[ASYNC_FLAG] = '1';
    const different = [
      'bus.on("data", (x) => { db.query(x); });',
      'bus.emit("other", req.query.x);',
    ].join('\n');
    expect(asyncFindings(different)).toEqual([]);
    const unresolved = [
      'bus.on("data", (x) => { db.query(x); });',
      'getBus().emit("data", req.query.x);',
    ].join('\n');
    expect(asyncFindings(unresolved)).toEqual([]);
  });
});
