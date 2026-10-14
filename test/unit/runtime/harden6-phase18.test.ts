import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scanTextForSecrets } from '../../../src/modules/secrets/index.js';
import {
  addThreat,
  clearRaspEvents,
  clearThreats,
  decideResponse,
  decideSink,
  disableRasp,
  egressAllowed,
  emitVirtualPatches,
  enableRasp,
  getRaspEvents,
  honeyInit,
  isHoneyCanary,
  isIpBlocked,
  loadVirtualPatches,
  raspContext,
  raspModeFor,
  threatScore,
} from '../../../src/runtime/rasp/index.js';
import { contextFromRequest } from '../../../src/runtime/rasp/context.js';

afterEach(() => {
  disableRasp();
  clearRaspEvents();
  clearThreats();
});

describe('harden-6 vpatch route/sink targeting and revert', () => {
  it('forces block only on the targeted route+sink and reverts when the finding disappears', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-h6-vpatch-'));
    const out = join(dir, 'vpatches.json');
    try {
      emitVirtualPatches(
        [{ ruleId: 'SAST-SQLI-001', file: 'app/routes/login.js', message: 'SQLi on /login' }],
        out,
      );
      enableRasp({ experimental: true, mode: 'monitor', virtualPatches: loadVirtualPatches(out) });
      expect(raspModeFor('/login', 'sql')).toBe('block');
      expect(raspModeFor('/login', 'shell')).toBe('monitor');
      expect(raspModeFor('/other', 'sql')).toBe('monitor');
      const payload = "' OR 1=1--";
      expect(decideSink('sql', `SELECT * FROM t WHERE n = '${payload}'`, contextFromRequest({ path: '/login', query: { q: payload } })).block).toBe(true);

      emitVirtualPatches([], out);
      disableRasp();
      enableRasp({ experimental: true, mode: 'monitor', virtualPatches: loadVirtualPatches(out) });
      expect(raspModeFor('/login', 'sql')).toBe('monitor');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('harden-6 egress allow/deny', () => {
  it('handles exact hosts, wildcard subdomains, and IP literals', () => {
    const allow = ['api.stripe.com', '*.amazonaws.com', '127.0.0.1'];
    expect(egressAllowed('api.stripe.com', allow)).toBe(true);
    expect(egressAllowed('s3.amazonaws.com', allow)).toBe(true);
    expect(egressAllowed('foo.bar.amazonaws.com', allow)).toBe(true);
    expect(egressAllowed('amazonaws.com', allow)).toBe(false);
    expect(egressAllowed('evilamazonaws.com', allow)).toBe(false);
    expect(egressAllowed('s3.amazonaws.com.evil.example', allow)).toBe(false);
    expect(egressAllowed('127.0.0.1', allow)).toBe(true);
    expect(egressAllowed('10.0.0.1', allow)).toBe(false);
    expect(egressAllowed('evil.example', allow)).toBe(false);
  });
});

describe('harden-6 threat score transitions and auto-block opt-in', () => {
  it('transitions log → challenge → block and expires a block', () => {
    expect(decideResponse(1)).toBe('log');
    expect(decideResponse(4)).toBe('log');
    expect(decideResponse(5)).toBe('challenge');
    expect(decideResponse(9)).toBe('challenge');
    expect(decideResponse(10)).toBe('block');
    addThreat('203.0.113.50', 'honey');
    addThreat('203.0.113.50', 'honey');
    expect(threatScore('203.0.113.50')).toBeGreaterThanOrEqual(10);
    expect(isIpBlocked('203.0.113.50')).toBe(false);
    enableRasp({ experimental: true, mode: 'monitor', threatAutoBlock: true, threatMaxBlockMs: 50 });
    addThreat('203.0.113.51', 'honey');
    addThreat('203.0.113.51', 'honey');
    expect(isIpBlocked('203.0.113.51')).toBe(true);
    const later = Date.now() + 200;
    expect(isIpBlocked('203.0.113.51', later)).toBe(false);
  });
});

describe('harden-6 honeytokens', () => {
  it('writes fake decoys that secrets do not flag, gitignores them, and treats credential use as critical', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-h6-honey-'));
    try {
      const canaries = honeyInit(dir);
      expect(canaries.awsKey).not.toMatch(/^AKIA/);
      expect(canaries.dbUrl).not.toMatch(/:\/\/[^:]+:[^@]+@/);
      const backup = readFileSync(join(dir, '.env.backup'), 'utf8');
      const honeyJson = readFileSync(join(dir, '.fullshield-honey.json'), 'utf8');
      expect(scanTextForSecrets('.env.backup', backup)).toEqual([]);
      expect(scanTextForSecrets('.fullshield-honey.json', honeyJson)).toEqual([]);
      const gi = readFileSync(join(dir, '.gitignore'), 'utf8');
      expect(gi).toMatch(/\.env\.backup/);
      expect(gi).toMatch(/\.fullshield-honey\.json/);

      enableRasp({ experimental: true, mode: 'block' });
      const mw = raspContext();
      const blocked: number[] = [];
      const res = {
        status(code: number) {
          blocked.push(code);
          return { json() { return undefined; } };
        },
      };
      mw({ path: '/admin.php', ip: '203.0.113.60' }, res, () => undefined);
      mw({ path: '/admin.php', ip: '203.0.113.60' }, res, () => undefined);
      expect(blocked).toEqual([]);
      const routeEvents = getRaspEvents().filter((e) => e.ruleId === 'RASP-HONEY-001' && e.sample === 'honeytoken');
      expect(routeEvents.length).toBeGreaterThan(0);
      expect(routeEvents.every((e) => e.severity === 'low')).toBe(true);
      expect(routeEvents[routeEvents.length - 1]?.count).toBeGreaterThanOrEqual(2);
      expect(isIpBlocked('203.0.113.60')).toBe(false);

      mw({ path: '/ok', ip: '203.0.113.61', query: { k: canaries.awsKey } }, res, () => undefined);
      const cred = getRaspEvents().find((e) => e.sample === 'canary-credential');
      expect(cred?.severity).toBe('critical');
      expect(isHoneyCanary(canaries.awsKey)).toBe(true);
      expect(isIpBlocked('203.0.113.61')).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('does not overwrite an existing .gitignore entry', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fullshield-h6-gi-'));
    try {
      writeFileSync(join(dir, '.gitignore'), '.env.backup\n', 'utf8');
      honeyInit(dir);
      const gi = readFileSync(join(dir, '.gitignore'), 'utf8');
      expect(gi.match(/\.env\.backup/g)?.length).toBe(1);
      expect(existsSync(join(dir, '.env.backup'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
