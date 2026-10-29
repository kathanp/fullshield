import { afterEach, describe, expect, it } from 'vitest';

import { disableRasp, emitRaspEvent, enableRasp, getRaspEvents, raspModeFor } from '../../../src/runtime/rasp/enable.js';
import { guardMode, resetWebhookRate, webhookFor } from '../../../src/runtime/exp/p567.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_RUNTIME_GUARD';

afterEach(() => {
  delete process.env[FLAG];
  resetWebhookRate();
  disableRasp();
});

describe('phase 567 runtime guard', () => {
  it('returns the requested mode and no webhook body when the flag is off', () => {
    expect(guardMode('block', 'ssrf')).toBe('block');
    expect(guardMode('monitor', 'sql')).toBe('monitor');
    expect(webhookFor('sql', 'block', 'RASP-SQL-001', 1_000)).toBeUndefined();
  });

  it('blocks only sql and shell when the flag is on', () => {
    process.env[FLAG] = '1';
    expect(guardMode('block', 'sql')).toBe('block');
    expect(guardMode('block', 'shell')).toBe('block');
    for (const kind of ['path', 'nosql', 'ssrf', 'proto', 'ssti']) {
      expect(guardMode('block', kind)).toBe('monitor');
    }
    expect(guardMode('monitor', 'sql')).toBe('monitor');
  });

  it('emits at most five webhook bodies per 60 seconds and omits the sample', () => {
    process.env[FLAG] = '1';
    const start = 1_000_000;
    const bodies: string[] = [];
    for (let i = 0; i < 5; i += 1) {
      const body = webhookFor('sql', 'block', 'RASP-SQL-001', start + i);
      expect(body).toBeTypeOf('string');
      bodies.push(body as string);
    }
    expect(webhookFor('sql', 'block', 'RASP-SQL-001', start + 5)).toBeUndefined();
    expect(webhookFor('shell', 'monitor', 'RASP-SHELL-001', start + 60_000)).toContain('"action":"monitor"');
    const first = bodies[0];
    expect(first).toBeTypeOf('string');
    if (first === undefined) {return;}
    const parsed = JSON.parse(first) as Record<string, unknown>;
    expect(parsed).toEqual({ schema: 1, kind: 'sql', action: 'block', ruleId: 'RASP-SQL-001' });
    expect(parsed.sample).toBeUndefined();
    expect(parsed.path).toBeUndefined();
    expect(parsed.ip).toBeUndefined();
  });

  it('narrows rasp block mode only while the flag is on', () => {
    enableRasp({ experimental: true, mode: 'block' });
    expect(raspModeFor('/pay', 'ssrf')).toBe('block');
    process.env[FLAG] = '1';
    expect(raspModeFor('/pay', 'sql')).toBe('block');
    expect(raspModeFor('/pay', 'ssrf')).toBe('monitor');
  });

  it('attaches webhook JSON to the event that was just recorded', () => {
    process.env[FLAG] = '1';
    enableRasp({ experimental: true, mode: 'block' });
    emitRaspEvent({ ruleId: 'RASP-SQL-001', path: '/pay', ip: '127.0.0.1', sample: 'secret' });
    expect(raspModeFor('/pay', 'sql')).toBe('block');
    const sql = getRaspEvents()[0];
    expect(sql?.webhookJson).toContain('"kind":"sql"');
    expect(sql?.webhookJson).not.toContain('secret');
    emitRaspEvent({ ruleId: 'RASP-SSRF-001', path: '/pay', ip: '127.0.0.1', sample: 'secret' });
    expect(raspModeFor('/pay', 'ssrf')).toBe('monitor');
    expect(getRaspEvents()[1]?.webhookJson).toContain('"action":"monitor"');
  });
});
