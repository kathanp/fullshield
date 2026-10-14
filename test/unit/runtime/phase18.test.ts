import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  addThreat,
  clearRaspEvents,
  contextFromRequest,
  decideResponse,
  decideSink,
  disableRasp,
  egressAllowed,
  emitVirtualPatches,
  enableRasp,
  getRaspEvents,
  honeyInit,
  isHoneyCanary,
  isHoneyRoute,
  loadVirtualPatches,
  patchForcesBlock,
  raspContext,
  raspModeFor,
  threatScore,
} from '../../../src/runtime/rasp/index.js';

afterEach(() => {
  disableRasp();
  clearRaspEvents();
});

describe('Phase 18 virtual patches (experimental)', () => {
  it('emits vpatches.json from findings and forces block on the matching route', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-vpatch-'));
    const out = join(dir, 'vpatches.json');
    try {
      emitVirtualPatches(
        [
          {
            ruleId: 'SAST-SQLI-001',
            file: 'app/routes/login.js',
            line: 12,
            message: 'SQLi on /login',
          },
        ],
        out,
      );
      const patches = loadVirtualPatches(out);
      expect(patches).toEqual([
        expect.objectContaining({
          ruleId: 'SAST-SQLI-001',
          file: 'app/routes/login.js',
          line: 12,
          sink: 'sql',
          route: '/login',
        }),
      ]);
      expect(patchForcesBlock(patches, '/login', 'sql')).toBe(true);
      expect(patchForcesBlock(patches, '/other', 'sql')).toBe(false);
      enableRasp({ experimental: true, mode: 'monitor', virtualPatches: patches });
      expect(raspModeFor('/login', 'sql')).toBe('block');
      expect(raspModeFor('/other', 'sql')).toBe('monitor');
      const payload = "' OR 1=1--";
      const ctx = contextFromRequest({ path: '/login', query: { q: payload } });
      expect(decideSink('sql', `SELECT * FROM t WHERE n = '${payload}'`, ctx).block).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Phase 18 egress allowlist (experimental)', () => {
  it('allows listed hosts and wildcard suffixes; blocks others', () => {
    const allow = ['api.stripe.com', '*.amazonaws.com'];
    expect(egressAllowed('api.stripe.com', allow)).toBe(true);
    expect(egressAllowed('s3.amazonaws.com', allow)).toBe(true);
    expect(egressAllowed('evil.example', allow)).toBe(false);
  });
});

describe('Phase 18 honeytokens (experimental)', () => {
  it('writes decoy files and treats decoy routes / canary values as hits', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-honey-'));
    try {
      const canaries = honeyInit(dir);
      const backup = readFileSync(join(dir, '.env.backup'), 'utf8');
      expect(backup).toContain(canaries.awsKey);
      expect(backup).toContain(canaries.dbUrl);
      expect(isHoneyRoute('/admin.php')).toBe(true);
      expect(isHoneyRoute('/.git/config')).toBe(true);
      expect(isHoneyRoute('/wp-login.php')).toBe(true);
      expect(isHoneyRoute('/home')).toBe(false);
      expect(isHoneyCanary(canaries.awsKey)).toBe(true);
      expect(isHoneyCanary('normal text')).toBe(false);
      enableRasp({ experimental: true, mode: 'monitor' });
      const mw = raspContext();
      mw({ path: '/admin.php', ip: '203.0.113.8' }, { status() { return { json() { return undefined; } }; } }, () => undefined);
      expect(getRaspEvents().some((e) => e.ruleId === 'RASP-HONEY-001')).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Phase 18 threat score', () => {
  it('escalates log → challenge → block', () => {
    addThreat('203.0.113.9', 'honey');
    expect(threatScore('203.0.113.9')).toBeGreaterThan(0);
    expect(decideResponse(1)).toBe('log');
    expect(decideResponse(5)).toBe('challenge');
    expect(decideResponse(10)).toBe('block');
  });
});
