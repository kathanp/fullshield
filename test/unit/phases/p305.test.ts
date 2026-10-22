import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { analyzeCli, enabled, FLAG, scanTreeForCli } from '../../../src/phases/p305.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 305 cli', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeCli("program.option('--branch <branch>');\nexec('deploy ' + program.opts().branch);").findings).toEqual([]);
  });

  it('reports a low command finding and skips execFile, sql, and libraries', () => {
    process.env[FLAG] = '1';
    const hit = analyzeCli("const { program } = require('commander');\nprogram.option('--branch <branch>');\nexec('deploy ' + program.opts().branch);");
    expect(hit.findings[0]).toMatchObject({ origin: 'cli', severity: 'low', sinkClass: 'cmdi' });
    expect(analyzeCli("program.option('--branch <branch>');\nexecFile('git', ['log', '--', program.opts().branch]);").findings).toEqual([]);
    expect(analyzeCli("program.option('--q <q>');\ndb.query('select ' + program.opts().q);").findings).toEqual([]);
    expect(analyzeCli('function lib(x) { return x; }').findings).toEqual([]);
    expect(scanTreeForCli(join(import.meta.dirname, '../../..', 'test/fixtures/clean-app'))).toEqual([]);
  });
});
