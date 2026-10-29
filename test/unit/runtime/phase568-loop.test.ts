import { afterEach, describe, expect, it } from 'vitest';

import {
  confirmAllowsPass,
  matchingSinkLines,
  responseWithinCap,
  runtimeMode,
  sqlFingerprint,
} from '../../../src/runtime/exp/p568.js';
import {
  clearRaspEvents,
  disableRasp,
  emitRaspEvent,
  enableRaspFromEnv,
  getRaspEvents,
  raspMode,
  raspModeFor,
} from '../../../src/runtime/rasp/enable.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_RUNTIME_GUARD';

afterEach(() => {
  delete process.env[FLAG];
  delete process.env.FULLSHIELD_EXPERIMENTAL_RASP;
  delete process.env.FULLSHIELD_RASP_MODE;
  clearRaspEvents();
  disableRasp();
});

describe('phase 568 runtime loop', () => {
  it('does nothing extra when the flag is off', () => {
    expect(sqlFingerprint("select 'secret' from t where id = 7")).toBeUndefined();
    expect(matchingSinkLines("db.query('x')\n", 'abc')).toEqual([]);
    expect(confirmAllowsPass([{ status: 'unconfirmed' }])).toBe(true);
    expect(responseWithinCap(5000)).toBe(true);
    expect(runtimeMode('block')).toBe('block');
    expect(runtimeMode('monitor')).toBe('monitor');
  });

  it('hashes the collapsed statement and keeps webhook keys', () => {
    process.env[FLAG] = '1';
    const a = sqlFingerprint("select 'secret' from t where id = 7");
    const b = sqlFingerprint("select 'other' from t where id = 99");
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{8}$/);
    emitRaspEvent({
      ruleId: 'RASP-SQL-001',
      path: '/q',
      ip: '127.0.0.1',
      sample: "select 'secret' from t where id = 7",
    });
    expect(raspModeFor('/q', 'sql')).toBe('monitor');
    const event = getRaspEvents()[0];
    expect(event?.fingerprint).toBe(a);
    const body = event?.webhookJson;
    expect(body).toBeTypeOf('string');
    if (body === undefined) {return;}
    expect(Object.keys(JSON.parse(body) as object).sort()).toEqual(['action', 'kind', 'ruleId', 'schema']);
    expect(body).not.toContain('secret');
  });

  it('reports query lines for a non-empty fingerprint', () => {
    process.env[FLAG] = '1';
    const fp = sqlFingerprint('select 1');
    expect(fp).toBeTypeOf('string');
    if (fp === undefined) {return;}
    expect(matchingSinkLines("const a = 1;\ndb.query(name);\nprisma.$queryRaw`x`;\n", fp)).toEqual([2, 3]);
    expect(matchingSinkLines("db.query(name)\n", '')).toEqual([]);
  });

  it('treats unconfirmed as not a pass only while the flag is on', () => {
    expect(confirmAllowsPass([{ status: 'confirmed' }])).toBe(true);
    process.env[FLAG] = '1';
    expect(confirmAllowsPass([{ status: 'confirmed' }])).toBe(true);
    expect(confirmAllowsPass([{ status: 'unconfirmed' }])).toBe(false);
    expect(confirmAllowsPass([])).toBe(true);
  });

  it('marks a sample over 4096 bytes and does not mark a smaller one', () => {
    process.env[FLAG] = '1';
    expect(responseWithinCap(4096)).toBe(true);
    expect(responseWithinCap(4097)).toBe(false);
    const sample = 'x'.repeat(4097);
    emitRaspEvent({ ruleId: 'RASP-SQL-001', path: '/q', ip: '127.0.0.1', sample });
    raspModeFor('/q', 'sql');
    expect(getRaspEvents()[0]?.overCap).toBe(true);
  });

  it('uses block-experimental as the only block name while the flag is on', () => {
    process.env.FULLSHIELD_EXPERIMENTAL_RASP = '1';
    process.env.FULLSHIELD_RASP_MODE = 'block';
    enableRaspFromEnv();
    expect(raspMode()).toBe('block');
    process.env[FLAG] = '1';
    process.env.FULLSHIELD_RASP_MODE = 'block';
    enableRaspFromEnv();
    expect(raspMode()).toBe('monitor');
    process.env.FULLSHIELD_RASP_MODE = 'block-experimental';
    enableRaspFromEnv();
    expect(raspMode()).toBe('block');
  });
});
