import { describe, expect, it } from 'vitest';

import { median, regressed } from '../../../bench/perf.mjs';
import { parseCacheKey, parsePoolEnabled, parsePoolSize, parseWithPool } from '../../../src/core/parse-pool.js';
import { findingsFromAst, parseSource } from '../../../src/modules/sast/engine.js';
import type { AstNode } from '../../../src/modules/sast/types.js';

const source = `
  const { exec } = require('child_process');
  function handler(req, res) {
    exec(req.query.cmd);
  }
`;

describe('Phase 42 parse pool', () => {
  it('flags a p50 that is more than 15% slower', () => {
    expect(median([30, 10, 20])).toBe(20);
    expect(median([4, 2])).toBe(3);
    expect(regressed(100, 120)).toBe(true);
    expect(regressed(100, 110)).toBe(false);
    expect(regressed(0, 50)).toBe(false);
  });

  it('returns the same command-injection finding as the in-process parser', async () => {
    const direct = findingsFromAst('app.js', source, await parseSource(source));
    const [pooled] = await parseWithPool([source]);
    const viaWorker = findingsFromAst('app.js', source, pooled as AstNode);
    expect(viaWorker.map((f) => `${f.ruleId}:${f.line}`)).toEqual(direct.map((f) => `${f.ruleId}:${f.line}`));
  });

  it('keys the cache by version and content, and honors the worker count', async () => {
    expect(parseCacheKey('a')).not.toBe(parseCacheKey('b'));
    expect(parsePoolEnabled()).toBe(false);
    process.env.FULLSHIELD_PARSE_POOL = '1';
    process.env.FULLSHIELD_PARSE_WORKERS = '2';
    try {
      expect(parsePoolEnabled()).toBe(true);
      expect(parsePoolSize()).toBe(2);
      process.env.FULLSHIELD_PARSE_WORKERS = '0';
      expect(parsePoolSize()).toBeGreaterThanOrEqual(1);
      process.env.FULLSHIELD_PARSE_WORKERS = 'nope';
      expect(parsePoolSize()).toBeGreaterThanOrEqual(1);
      const first = await parseWithPool([source]);
      const second = await parseWithPool([source]);
      expect(second[0]).toBe(first[0]);
    } finally {
      delete process.env.FULLSHIELD_PARSE_POOL;
      delete process.env.FULLSHIELD_PARSE_WORKERS;
    }
  });
});
