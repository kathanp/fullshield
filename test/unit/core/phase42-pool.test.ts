import { describe, expect, it } from 'vitest';

import { parseCacheKey, parsePoolSize, parseWithPool } from '../../../src/core/parse-pool.js';
import { findingsFromAst, parseSource } from '../../../src/modules/sast/engine.js';
import type { AstNode } from '../../../src/modules/sast/types.js';

const source = `
  const { exec } = require('child_process');
  function handler(req, res) {
    exec(req.query.cmd);
  }
`;

describe('Phase 42 parse pool', () => {
  it('returns the same command-injection finding as the in-process parser', async () => {
    const direct = findingsFromAst('app.js', source, await parseSource(source));
    const [pooled] = await parseWithPool([source]);
    const viaWorker = findingsFromAst('app.js', source, pooled as AstNode);
    expect(viaWorker.map((f) => `${f.ruleId}:${f.line}`)).toEqual(direct.map((f) => `${f.ruleId}:${f.line}`));
  });

  it('keys the cache by version and content, and keeps at least one worker', () => {
    expect(parseCacheKey('a')).not.toBe(parseCacheKey('b'));
    expect(parsePoolSize()).toBeGreaterThanOrEqual(1);
  });
});
