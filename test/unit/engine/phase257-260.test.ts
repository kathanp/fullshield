import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

import { afterEach, describe, expect, it } from 'vitest';

import { loadAdvisorySymbols, symbolReach, ADVSYMBOLS_FLAG } from '../../../src/engine/advisory-symbols.js';
import { functionReachable, upgradeReach, DEPGRAPH_FLAG } from '../../../src/engine/depgraph.js';
import { dropsStringInjection, resolveImplementor, sqlFindingForType, IRTYPES_FLAG } from '../../../src/engine/irtypes.js';

afterEach(() => {
  delete process.env[ADVSYMBOLS_FLAG];
  delete process.env[DEPGRAPH_FLAG];
  delete process.env[IRTYPES_FLAG];
});

describe('phase 257 types', () => {
  it('drops string-injection labels for number and not for string or any', () => {
    expect(dropsStringInjection('number')).toBe(true);
    expect(dropsStringInjection('boolean')).toBe(true);
    expect(dropsStringInjection("'a'|'b'")).toBe(true);
    expect(dropsStringInjection('string')).toBe(false);
    expect(dropsStringInjection('any')).toBe(false);
    expect(sqlFindingForType('number', 'sqli')).toBe(false);
    process.env[IRTYPES_FLAG] = '1';
    expect(sqlFindingForType('number', 'sqli')).toBe(false);
    expect(sqlFindingForType('string', 'sqli')).toBe(true);
    expect(sqlFindingForType('any', 'sqli')).toBe(true);
    expect(resolveImplementor([{ iface: 'Repo', method: 'find', className: 'SqlRepo' }], 'Repo', 'find')).toBe('SqlRepo');
    expect(resolveImplementor([
      { iface: 'Repo', method: 'find', className: 'A' },
      { iface: 'Repo', method: 'find', className: 'B' },
    ], 'Repo', 'find')).toBeUndefined();
  });
});

describe('phase 259 dep graph', () => {
  it('upgrades a called vulnerable export and never downgrades', () => {
    process.env[DEPGRAPH_FLAG] = '1';
    const edges = new Map([
      ['app.main', ['a.handle']],
      ['a.handle', ['b.parse']],
    ]);
    const read: string[] = [];
    const hit = functionReachable({
      current: 'reachable-via-dependency',
      rootExport: 'app.main',
      vulnerable: 'b.parse',
      edges,
      malicious: new Set(),
      readPackage: (name) => {
        read.push(name);
      },
    });
    expect(hit.reachability).toBe('function-reachable-via-dependency');
    expect(hit.path).toEqual(['app.main', 'a.handle', 'b.parse']);
    const missed = functionReachable({
      current: 'reachable-via-dependency',
      rootExport: 'app.main',
      vulnerable: 'b.parse',
      edges: new Map([['app.main', ['a.handle']]]),
      malicious: new Set(),
      readPackage: () => undefined,
    });
    expect(missed.reachability).toBe('reachable-via-dependency');
    const kept = functionReachable({
      current: 'function-reachable-via-dependency',
      rootExport: 'app.main',
      vulnerable: 'b.parse',
      edges: new Map(),
      malicious: new Set(),
      readPackage: () => undefined,
    });
    expect(kept.reachability).toBe('function-reachable-via-dependency');
    expect(upgradeReach('function-reachable-via-dependency', 'reachable-via-dependency')).toBe('function-reachable-via-dependency');
  });

  it('does not read a malicious package', () => {
    process.env[DEPGRAPH_FLAG] = '1';
    const read: string[] = [];
    functionReachable({
      current: 'reachable-via-dependency',
      rootExport: 'app.main',
      vulnerable: 'b.parse',
      edges: new Map([['app.main', ['b.parse']]]),
      malicious: new Set(['b']),
      readPackage: (name) => {
        read.push(name);
      },
    });
    expect(read).not.toContain('b');
  });

  it('stays idle when the flag is off and stops at the depth cap', () => {
    const idle = functionReachable({
      current: 'not-imported',
      rootExport: 'app.main',
      vulnerable: 'd.fn',
      edges: new Map([['app.main', ['a.fn']]]),
      malicious: new Set(),
      readPackage: () => undefined,
    });
    expect(idle).toEqual({ reachability: 'not-imported', path: [], read: [] });
    process.env[DEPGRAPH_FLAG] = '1';
    const read: string[] = [];
    const capped = functionReachable({
      current: 'imported-not-called',
      rootExport: 'app.main',
      vulnerable: 'e.fn',
      edges: new Map([
        ['app.main', ['app.helper', 'a.fn']],
        ['app.helper', ['app.main']],
        ['a.fn', ['b.fn']],
        ['b.fn', ['c.fn']],
        ['c.fn', ['e.fn']],
      ]),
      malicious: new Set(['skip']),
      readPackage: (name) => {
        read.push(name);
      },
    });
    expect(capped.reachability).toBe('reachable-via-dependency');
    expect(read.filter((name) => name === 'app')).toHaveLength(1);
    expect(upgradeReach('not-imported', 'reachable')).toBe('reachable');
    delete process.env[DEPGRAPH_FLAG];
  });
});

describe('phase 260 advisory symbols', () => {
  it('rejects a row without a source and does not mark the fixture reviewed', () => {
    const raw = JSON.parse(readFileSync('models/advisory-symbols.json', 'utf8')) as { rows: { reviewed: boolean }[] };
    expect(raw.rows.every((row) => row.reviewed === false)).toBe(true);
    expect(() => loadAdvisorySymbols({ rows: [{ osvId: 'X', package: 'p', affectedExports: [], reviewed: false }] })).toThrow(/source/);
    const script = readFileSync('scripts/advisory-symbols-candidates.mjs', 'utf8');
    expect(script.includes('reviewed: true')).toBe(false);
    const rows = loadAdvisorySymbols(raw);
    process.env[ADVSYMBOLS_FLAG] = '1';
    expect(symbolReach(rows[0]!, [])).toMatchObject({ reachability: 'symbol-not-called', label: 'unreviewed' });
    expect(symbolReach(rows[0]!, ['parse'])).toMatchObject({ reachability: 'symbol-reachable', label: 'unreviewed' });
    const listed = spawnSync(process.execPath, ['scripts/advisory-symbols-candidates.mjs', '--write'], { encoding: 'utf8' });
    expect(listed.status).not.toBe(0);
  });

  it('rejects malformed rows and labels a reviewed symbol only under the flag', () => {
    expect(() => loadAdvisorySymbols(null)).toThrow(/rows/);
    expect(() => loadAdvisorySymbols(1)).toThrow(/rows/);
    expect(() => loadAdvisorySymbols({})).toThrow(/rows/);
    expect(() => loadAdvisorySymbols({ rows: 'no' })).toThrow(/rows/);
    expect(() => loadAdvisorySymbols({ rows: [null] })).toThrow(/source/);
    expect(() => loadAdvisorySymbols({ rows: [1] })).toThrow(/source/);
    expect(() => loadAdvisorySymbols({ rows: [{ source: '', osvId: 'a', package: 'p', affectedExports: [] }] })).toThrow(/source/);
    expect(() => loadAdvisorySymbols({ rows: [{ source: 's', package: 'p', affectedExports: [] }] })).toThrow(/source/);
    expect(() => loadAdvisorySymbols({ rows: [{ source: 's', osvId: 'a', package: 1, affectedExports: [] }] })).toThrow(/source/);
    expect(() => loadAdvisorySymbols({ rows: [{ source: 's', osvId: 'a', package: 'p', affectedExports: 'x' }] })).toThrow(/source/);
    const rows = loadAdvisorySymbols({
      rows: [{ source: 's', osvId: 'OSV', package: 'p', affectedExports: ['ok', 1, null], reviewed: true }],
    });
    expect(rows[0]?.affectedExports).toEqual(['ok']);
    expect(symbolReach(rows[0]!, ['ok'])).toBeUndefined();
    process.env[ADVSYMBOLS_FLAG] = '1';
    expect(symbolReach(rows[0]!, ['ok'])).toMatchObject({ reachability: 'symbol-reachable', label: 'reviewed' });
    delete process.env[ADVSYMBOLS_FLAG];
  });
});
