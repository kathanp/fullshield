import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

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
    const result = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import { median, regressed } from './bench/perf.mjs';
         console.log(JSON.stringify({
           m1: median([30, 10, 20]),
           m2: median([4, 2]),
           r1: regressed(100, 120),
           r2: regressed(100, 110),
           r3: regressed(0, 50),
         }));`,
      ],
      { encoding: 'utf8' },
    );
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ m1: 20, m2: 3, r1: true, r2: false, r3: false });
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
