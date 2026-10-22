import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, readLockedVersion, resetVersionCache, selectRow } from '../../../src/phases/p310.js';

const ROWS = [
  { id: 'express-4', appliesTo: '>=4 <5' },
  { id: 'express-5', appliesTo: '>=5 <6' },
];

afterEach(() => {
  delete process.env[FLAG];
  resetVersionCache();
});

describe('phase 310 version selector', () => {
  it('does not read appliesTo when the flag is off', () => {
    expect(enabled()).toBe(false);
    const rows = [{ id: 'x', get appliesTo(): string { throw new Error('read'); } }];
    expect(selectRow(rows, '1.0.0', 'node_modules/express')).toEqual({ row: null, versionAssumed: false, fallback: false, events: [] });
  });

  it('selects different rows, a gap, and a git dependency', () => {
    process.env[FLAG] = '1';
    const v4 = selectRow(ROWS, '4.18.2', 'node_modules/express');
    const v5 = selectRow(ROWS, '5.0.0', 'node_modules/app/node_modules/express');
    expect(v4.row?.id).toBe('express-4');
    expect(v5.row?.id).toBe('express-5');
    expect(v4.row?.id).not.toBe(v5.row?.id);
    const again = selectRow(ROWS, '9.9.9', 'node_modules/express');
    expect(again).toBe(v4);
    const gap = selectRow([{ id: 'sequelize-6', appliesTo: '>=6 <7' }], '5.0.0', 'node_modules/sequelize');
    expect(gap.row).toBeNull();
    expect(gap.fallback).toBe(true);
    expect(gap.events[0]?.reason).toBe('version-gap');
    const git = selectRow(ROWS, 'git+https://github.com/expressjs/express.git#v4.0.0', 'node_modules/git-express');
    expect(git.versionAssumed).toBe(true);
    expect(git.row?.id).toBe('express-5');
    expect(() => selectRow([{ id: 'a', appliesTo: '>=4 <6' }, { id: 'b', appliesTo: '>=5 <7' }], '5.1.0', 'node_modules/ambiguous')).toThrow(/ambiguous/);
    expect(() => selectRow([{ id: 'bare' }], '1.0.0', 'node_modules/bare')).toThrow(/appliesTo/);
  });

  it('reads only the locked path', () => {
    const lock = JSON.stringify({
      packages: {
        'node_modules/express': { version: '4.18.2' },
        'node_modules/app/node_modules/express': { version: '5.1.0' },
      },
    });
    expect(readLockedVersion(lock, 'node_modules/express')).toBe('4.18.2');
    expect(readLockedVersion(lock, 'node_modules/app/node_modules/express')).toBe('5.1.0');
    const missing = selectRow(ROWS, null, 'node_modules/deleted');
    expect(missing.versionAssumed).toBe(false);
    process.env[FLAG] = '1';
    const assumed = selectRow(ROWS, null, 'node_modules/deleted');
    expect(assumed.versionAssumed).toBe(true);
    expect(assumed.row?.id).toBe('express-5');
  });
});
