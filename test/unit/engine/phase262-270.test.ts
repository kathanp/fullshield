import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { afterEach, describe, expect, it } from 'vitest';

import { INCR_FLAG, sameAfterEdits } from '../../../src/engine/incr.js';
import { PROOF_FLAG, buildProof } from '../../../src/engine/proof.js';
import { markObserved, observeOrFailOpen, RUNTIMEREACH_FLAG } from '../../../src/engine/runtimereach.js';
import { SHARDS_FLAG, planShards, summariesMatch } from '../../../src/engine/shards.js';
import { SINKCATALOG_FLAG, catalogGaps, gapMarkdown, readSinkCatalog } from '../../../src/engine/sinks.js';

afterEach(() => {
  delete process.env[PROOF_FLAG];
  delete process.env[SINKCATALOG_FLAG];
  delete process.env[RUNTIMEREACH_FLAG];
  delete process.env[INCR_FLAG];
  delete process.env[SHARDS_FLAG];
});

describe('phase 262 proof', () => {
  it('verifies a connected proof and rejects a corrupted one', () => {
    const dir = mkdtempSync(join(tmpdir(), 'proof-'));
    writeFileSync(join(dir, 'app.js'), 'const x = req.query.user;\ndb.query(x);\n');
    process.env[PROOF_FLAG] = '1';
    const proof = buildProof({
      file: 'app.js',
      sourceLine: 1,
      sinkLine: 2,
      sinkClass: 'sqli',
      labelsAtSink: ['sqli'],
      steps: [
        { file: 'app.js', line: 1, op: 'load', value: 'x' },
        { file: 'app.js', line: 2, op: 'query', value: 'x' },
      ],
    });
    const proofPath = join(dir, 'proof.json');
    writeFileSync(proofPath, JSON.stringify(proof));
    const ok = spawnSync(process.execPath, ['scripts/verify-proof.mjs', proofPath, dir], { encoding: 'utf8' });
    expect(ok.status).toBe(0);
    const bad = { ...proof, steps: [{ file: 'app.js', line: 1, op: 'load', value: 'missing-name' }, proof!.steps[1]] };
    const badPath = join(dir, 'bad.json');
    writeFileSync(badPath, JSON.stringify(bad));
    const failed = spawnSync(process.execPath, ['scripts/verify-proof.mjs', badPath, dir], { encoding: 'utf8' });
    expect(failed.status).not.toBe(0);
    expect(readFileSync('scripts/verify-proof.mjs', 'utf8').includes('src/engine')).toBe(false);
    delete process.env[PROOF_FLAG];
    expect(buildProof({ file: 'app.js', sourceLine: 1, sinkLine: 2, sinkClass: 'sqli', labelsAtSink: [], steps: [] })).toBeUndefined();
  });

  it('uses a source step when the proof has no operations', () => {
    process.env[PROOF_FLAG] = '1';
    expect(buildProof({
      file: 'app.js',
      sourceLine: 1,
      sinkLine: 2,
      sinkClass: 'sqli',
      labelsAtSink: [],
      steps: [],
    })?.source.kind).toBe('source');
    delete process.env[PROOF_FLAG];
  });
});

describe('phase 267 sink catalog', () => {
  it('accepts a documented gap and flags a sink with neither hook nor gap', () => {
    process.env[SINKCATALOG_FLAG] = '1';
    const raw = JSON.parse(readFileSync('models/sinks.json', 'utf8')) as { sinks: { runtimeHook: string | null; runtimeGap?: string }[] };
    const rows = readSinkCatalog(raw);
    expect(catalogGaps(rows)).toEqual([]);
    const missing = [{ package: 'pg', member: 'query', argIndex: 0, class: 'sqli', staticSupported: true, runtimeHook: null }];
    expect(catalogGaps(missing)).toHaveLength(1);
    expect(gapMarkdown(rows)).toContain('No undocumented gaps.');
    expect(gapMarkdown(missing)).toContain('pg.query');
    expect(readFileSync('RASP-SINKS.md', 'utf8')).toContain('runtimeGap');
  });

  it('ignores the catalog when the flag is off and skips rows that are not sinks', () => {
    expect(readSinkCatalog({ sinks: [{ package: 'pg', member: 'query' }] })).toEqual([]);
    process.env[SINKCATALOG_FLAG] = '1';
    expect(readSinkCatalog(null)).toEqual([]);
    expect(readSinkCatalog({})).toEqual([]);
    expect(readSinkCatalog({ sinks: 'no' })).toEqual([]);
    const rows = readSinkCatalog({
      sinks: [
        null,
        1,
        { package: 'p' },
        { package: 'p', member: 'm', argIndex: 'x', class: 1, runtimeHook: 1, runtimeGap: 1, staticSupported: false },
      ],
    });
    expect(rows).toEqual([{
      package: 'p',
      member: 'm',
      argIndex: 0,
      class: '',
      staticSupported: false,
      runtimeHook: null,
      runtimeGap: undefined,
    }]);
    expect(catalogGaps([
      { package: 'a', member: 'm', argIndex: 0, class: 'c', staticSupported: true, runtimeHook: 'hook' },
      { package: 'b', member: 'm', argIndex: 0, class: 'c', staticSupported: true, runtimeHook: null, runtimeGap: 'later' },
      { package: 'c', member: 'm', argIndex: 0, class: 'c', staticSupported: false, runtimeHook: 'hook' },
      { package: 'd', member: 'm', argIndex: 0, class: 'c', staticSupported: false, runtimeHook: null },
      { package: 'e', member: 'm', argIndex: 0, class: 'c', staticSupported: false, runtimeHook: '', runtimeGap: '' },
    ]).map((row) => row.package)).toEqual(['c']);
    expect(gapMarkdown([])).toContain('No undocumented gaps.');
    delete process.env[SINKCATALOG_FLAG];
  });
});

describe('phase 268 runtime reach', () => {
  it('marks a called export and does not downgrade an uncalled one', () => {
    process.env[RUNTIMEREACH_FLAG] = '1';
    const called = markObserved('reachable-via-dependency', 'b', 'parse', [{ module: 'b', exportName: 'parse', calls: 2 }]);
    expect(called.runtimeObserved).toBe(true);
    expect(called.reachability).toBe('reachable-via-dependency');
    const missed = markObserved('reachable', 'b', 'parse', [{ module: 'b', exportName: 'parse', calls: 0 }]);
    expect(missed.runtimeObserved).toBe(false);
    expect(missed.reachability).toBe('reachable');
    expect(observeOrFailOpen('reachable', () => { throw new Error('hook down'); }).reachability).toBe('reachable');
    expect(readFileSync('src/engine/runtimereach.ts', 'utf8').includes('fetch(')).toBe(false);
  });

  it('keeps the static result when the flag is off or the hook returns no rows', () => {
    expect(markObserved('reachable', 'b', 'parse', [{ module: 'b', exportName: 'parse', calls: 2 }])).toEqual({
      reachability: 'reachable',
      runtimeObserved: false,
    });
    process.env[RUNTIMEREACH_FLAG] = '1';
    expect(observeOrFailOpen('reachable', () => []).runtimeObserved).toBe(false);
    expect(observeOrFailOpen('reachable', () => [{ module: 'm', exportName: 'e', calls: 1 }]).runtimeObserved).toBe(true);
    expect(markObserved('reachable', 'b', 'parse', [{ module: 'other', exportName: 'parse', calls: 3 }]).runtimeObserved).toBe(false);
    delete process.env[RUNTIMEREACH_FLAG];
  });
});

describe('phase 269 incremental', () => {
  it('matches a cold result after 20 edits and skips untouched files', () => {
    process.env[INCR_FLAG] = '1';
    const initial = new Map([['a.js', 'a0'], ['b.js', 'b']]);
    const edits = Array.from({ length: 20 }, (_item, index) => ({ file: 'a.js', source: `a${index + 1}` }));
    const result = sameAfterEdits(initial, edits, (_file, source) => source);
    expect(result.equal).toBe(true);
    expect(result.recomputed.every((id) => id === 'ir:a.js')).toBe(true);
    expect(result.recomputed).toHaveLength(20);
  });
});

describe('phase 270 shards', () => {
  it('keeps export summaries under the memory cap for a synthetic million lines', () => {
    process.env[SHARDS_FLAG] = '1';
    const files = [
      { workspace: 'web', loc: 600_000, exports: ['page'] },
      { workspace: 'api', loc: 400_000, exports: ['route'] },
    ];
    expect(files.reduce((sum, file) => sum + file.loc, 0)).toBe(1_000_000);
    const plan = planShards(files, 500);
    expect(plan.evicted.length).toBeGreaterThan(0);
    expect(plan.exports).toEqual(['page', 'route']);
    expect(summariesMatch(files)).toBe(true);
    const small = [{ workspace: 'web', loc: 10, exports: ['page'] }];
    expect(planShards(small).evicted).toEqual([]);
  });
});
