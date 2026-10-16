import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import { leakBodies, NON_LUHN_PAN, STACK_TRACE, VISA_TEST_PAN, awsAccessKey } from './dlp-leaks.js';
import { createDlpInspector, DLP_FLAG, DLP_MAX_BYTES, isDlpEnabled } from '../../../src/runtime/dlp/index.js';
import { shieldGuard as expressGuard } from '../../../src/runtime/express.js';
import { shieldGuard as fastifyGuard } from '../../../src/runtime/fastify.js';
import { shieldGuard as honoGuard } from '../../../src/runtime/hono.js';
import { createInspector } from '../../../src/runtime/inspect.js';
import { shieldGuard as koaGuard } from '../../../src/runtime/koa.js';

const FLAG = DLP_FLAG;
const root = process.cwd();
const leaks = leakBodies();
const benign = JSON.parse(
  readFileSync(join(root, 'test/fixtures/dlp/benign-corpus.json'), 'utf8'),
) as { cases: Array<{ id: string; body: unknown }> };

function withFlag(on: boolean): void {
  if (on) process.env[FLAG] = '1';
  else delete process.env[FLAG];
}

afterEach(() => {
  delete process.env[FLAG];
});

function mustDlp(mode: 'monitor' | 'mask' | 'block') {
  const dlp = createDlpInspector({ dlp: { mode }, onEvent: vi.fn() });
  expect(dlp).toBeDefined();
  return dlp!;
}

function expressHarness(options: Parameters<typeof expressGuard>[0]) {
  const mw = expressGuard(options);
  let status = 200;
  let body: unknown;
  const res = {
    statusCode: 200,
    status(code: number) {
      status = code;
      this.statusCode = code;
      return {
        json: (b: unknown) => {
          status = code;
          body = b;
          return res;
        },
      };
    },
    json(b: unknown) {
      body = b;
      return res;
    },
    send(b: unknown) {
      body = b;
      return res;
    },
  };
  return {
    mw,
    res,
    next: vi.fn(),
    get status() {
      return status;
    },
    get body() {
      return body;
    },
  };
}

describe('Phase 32 — experimental response DLP', () => {
  describe('flag and prior inspect-only behavior', () => {
    it('isDlpEnabled is false without FULLSHIELD_EXPERIMENTAL_DLP=1', () => {
      withFlag(false);
      expect(isDlpEnabled()).toBe(false);
      expect(createDlpInspector({ dlp: { mode: 'mask' } })).toBeUndefined();
    });

    it('does not activate DLP when the flag is on but shieldGuard has no dlp option', () => {
      withFlag(true);
      expect(createDlpInspector({ mode: 'block' })).toBeUndefined();
    });

    it('shieldGuard without dlp option matches prior inspect-only behavior', () => {
      withFlag(true);
      const onEvent = vi.fn();
      const inspect = createInspector({ mode: 'block', onEvent });
      const blocked = inspect({ path: '/q', query: { q: "' OR 1=1--" } });
      expect(blocked.block).toBe(true);
      expect(blocked.event?.ruleId).toBe('RUNTIME-SQLI-001');

      const h = expressHarness({ mode: 'block', onEvent });
      h.mw({ path: '/ok', query: { q: 'hello' } }, h.res, h.next);
      expect(h.next).toHaveBeenCalledTimes(1);
      h.res.json(leaks.aws);
      expect(h.body).toEqual(leaks.aws);
      expect(JSON.stringify(h.body)).toContain(awsAccessKey());
      expect(
        onEvent.mock.calls.filter((c) => String((c[0] as { ruleId?: string }).ruleId ?? '').startsWith('DLP-')),
      ).toHaveLength(0);
    });

    it('ignores dlp option when the experimental flag is unset', () => {
      withFlag(false);
      const onEvent = vi.fn();
      const h = expressHarness({ dlp: { mode: 'mask' }, onEvent });
      h.mw({ path: '/me', query: {} }, h.res, h.next);
      expect(h.next).toHaveBeenCalledTimes(1);
      h.res.json(leaks.aws);
      expect(h.body).toEqual(leaks.aws);
      expect(onEvent).not.toHaveBeenCalled();
    });

    it('default scan on vulnerable-app and clean-app emits no DLP rule IDs', async () => {
      withFlag(false);
      const vuln = await scan({ cwd: join(root, 'test/fixtures/vulnerable-app'), offline: true });
      const clean = await scan({ cwd: join(root, 'test/fixtures/clean-app'), offline: true });
      const ids = [...vuln.findings, ...clean.findings].map((f) => f.ruleId);
      expect(ids.filter((id) => id.startsWith('DLP-'))).toEqual([]);

      withFlag(true);
      const vulnOn = await scan({ cwd: join(root, 'test/fixtures/vulnerable-app'), offline: true });
      const cleanOn = await scan({ cwd: join(root, 'test/fixtures/clean-app'), offline: true });
      const idsOn = [...vulnOn.findings, ...cleanOn.findings].map((f) => f.ruleId);
      expect(idsOn.filter((id) => id.startsWith('DLP-'))).toEqual([]);
    });
  });

  describe('leak fixtures (must detect)', () => {
    beforeEach(() => withFlag(true));

    it('detects reused secret patterns in JSON', () => {
      const dlp = mustDlp('monitor');
      for (const key of ['aws', 'stripe', 'github', 'slack', 'google', 'ai', 'pem', 'db'] as const) {
        const result = dlp.inspect(leaks[key], { path: '/leak' });
        expect(result.hits.some((h) => h.ruleId === 'DLP-SECRET-001'), key).toBe(true);
        expect(result.action).toBe('allow');
        expect(result.body).toEqual(leaks[key]);
      }
    });

    it('detects stack traces, internal IPs/hostnames, and Luhn cards', () => {
      const dlp = mustDlp('monitor');
      expect(dlp.inspect(leaks.stack, { path: '/err' }).hits.map((h) => h.ruleId)).toContain('DLP-STACK-001');
      expect(dlp.inspect(leaks.internalIp, { path: '/i' }).hits.map((h) => h.ruleId)).toContain('DLP-INTERNAL-001');
      expect(dlp.inspect(leaks.internalRfc1918b, { path: '/i' }).hits.map((h) => h.ruleId)).toContain('DLP-INTERNAL-001');
      expect(dlp.inspect(leaks.internalRfc1918c, { path: '/i' }).hits.map((h) => h.ruleId)).toContain('DLP-INTERNAL-001');
      expect(dlp.inspect(leaks.loopback, { path: '/i' }).hits.map((h) => h.ruleId)).toContain('DLP-INTERNAL-001');
      expect(dlp.inspect(leaks.localhost, { path: '/i' }).hits.map((h) => h.ruleId)).toContain('DLP-INTERNAL-001');
      expect(dlp.inspect(leaks.internalDns, { path: '/i' }).hits.map((h) => h.ruleId)).toContain('DLP-INTERNAL-001');
      expect(dlp.inspect(leaks.card, { path: '/pay' }).hits.map((h) => h.ruleId)).toContain('DLP-CARD-001');
      expect(dlp.inspect(leaks.cardDashed, { path: '/pay' }).hits.map((h) => h.ruleId)).toContain('DLP-CARD-001');
    });

    it('flags bulk emails only on a route that normally returns one', () => {
      const dlp = mustDlp('monitor');
      expect(dlp.inspect(leaks.oneEmail, { path: '/me' }).hits).toEqual([]);
      expect(dlp.inspect(leaks.oneEmail, { path: '/me' }).hits).toEqual([]);
      const burst = dlp.inspect(leaks.manyEmails, { path: '/me' });
      expect(burst.hits.map((h) => h.ruleId)).toContain('DLP-PII-001');

      const exportDlp = mustDlp('monitor');
      expect(exportDlp.inspect(leaks.manyEmails, { path: '/export' }).hits).toEqual([]);
      expect(exportDlp.inspect(leaks.manyEmails, { path: '/export' }).hits).toEqual([]);
      expect(exportDlp.inspect(leaks.manyEmails, { path: '/export' }).hits).toEqual([]);
    });
  });

  describe('negative fixtures (must not detect)', () => {
    beforeEach(() => withFlag(true));

    it('does not flag incomplete secrets, non-Luhn digits, or prose "at"', () => {
      const dlp = mustDlp('monitor');
      expect(dlp.inspect({ id: 'AKIA123' }, { path: '/n' }).hits).toEqual([]);
      expect(dlp.inspect({ token: 'sk-short' }, { path: '/n' }).hits).toEqual([]);
      expect(dlp.inspect({ order: NON_LUHN_PAN }, { path: '/n' }).hits).toEqual([]);
      expect(dlp.inspect({ error: 'Not found' }, { path: '/n' }).hits).toEqual([]);
      expect(dlp.inspect({ note: 'located at the front desk' }, { path: '/n' }).hits).toEqual([]);
      expect(dlp.inspect({ ip: '8.8.8.8' }, { path: '/n' }).hits).toEqual([]);
      expect(dlp.inspect({ host: 'api.example.com' }, { path: '/n' }).hits).toEqual([]);
      expect(dlp.inspect({ ip: '172.15.0.1' }, { path: '/n' }).hits).toEqual([]);
    });

    it('zero masking on the benign response corpus', () => {
      const dlp = mustDlp('mask');
      for (const c of benign.cases) {
        const result = dlp.inspect(c.body, { path: `/benign/${c.id}` });
        expect(result.hits, c.id).toEqual([]);
        expect(result.action, c.id).toBe('allow');
        expect(result.body, c.id).toEqual(c.body);
      }
    });
  });

  describe('modes, events, cap, budget', () => {
    beforeEach(() => withFlag(true));

    it('mask replaces leaks and block returns a generic 500', () => {
      const onEvent = vi.fn();
      const mask = createDlpInspector({ dlp: { mode: 'mask' }, onEvent })!;
      const masked = mask.inspect(leaks.aws, { path: '/x', ip: '203.0.113.9' });
      expect(masked.action).toBe('mask');
      expect(JSON.stringify(masked.body)).not.toContain(awsAccessKey());
      expect(onEvent).toHaveBeenCalled();
      const evt = onEvent.mock.calls[0]?.[0] as { ruleId: string; sample: string; path: string };
      expect(evt.ruleId).toBe('DLP-SECRET-001');
      expect(evt.path).toBe('/x');
      expect(evt.sample).not.toContain(awsAccessKey());

      const blocker = createDlpInspector({ dlp: { mode: 'block' }, onEvent })!;
      const blocked = blocker.inspect(leaks.stack, { path: '/x' });
      expect(blocked.action).toBe('block');
      expect(blocked.body).toEqual({ error: 'internal error' });
      expect(JSON.stringify(blocked.body)).not.toContain('at handle');
    });

    it('skips and counts responses over the 64KB cap even when they contain leaks', () => {
      const dlp = mustDlp('mask');
      const huge = `${awsAccessKey()}${'x'.repeat(DLP_MAX_BYTES)}`;
      const result = dlp.inspect(huge, { path: '/big' });
      expect(result.action).toBe('skip');
      expect(result.skippedOverCap).toBe(true);
      expect(result.body).toBe(huge);
      expect(result.hits).toEqual([]);
      expect(dlp.skippedOverCap).toBe(1);
    });

    it('enforces p95 extra < 1ms for responses ≤ 64KB', () => {
      const result = spawnSync(process.execPath, ['--expose-gc', join(root, 'scripts/dlp-bench.mjs')], {
        cwd: root,
        encoding: 'utf8',
      });
      expect(result.status).toBe(0);
      const p95 = Number(result.stdout.trim());
      expect(Number.isFinite(p95)).toBe(true);
      expect(p95).toBeLessThan(1);
    });
  });

  describe('adapters', () => {
    beforeEach(() => withFlag(true));

    it('Express mask/block inspect outgoing json', () => {
      const onEvent = vi.fn();
      const masked = expressHarness({ dlp: { mode: 'mask' }, onEvent });
      masked.mw({ path: '/me', ip: '198.51.100.1' }, masked.res, masked.next);
      masked.res.json(leaks.card);
      expect(JSON.stringify(masked.body)).not.toContain(VISA_TEST_PAN);
      expect(onEvent.mock.calls.some((c) => (c[0] as { ruleId: string }).ruleId === 'DLP-CARD-001')).toBe(true);

      const blocked = expressHarness({ dlp: { mode: 'block' }, onEvent });
      blocked.mw({ path: '/err' }, blocked.res, blocked.next);
      blocked.res.send(STACK_TRACE);
      expect(blocked.status).toBe(500);
      expect(blocked.body).toEqual({ error: 'internal error' });
    });

    it('Fastify onSend masks JSON payloads', () => {
      const onEvent = vi.fn();
      const plugin = fastifyGuard({ dlp: { mode: 'mask' }, onEvent });
      const hooks = new Map<string, Array<(...args: unknown[]) => void>>();
      plugin(
        {
          addHook(name, hook) {
            const list = hooks.get(name) ?? [];
            list.push(hook as (...args: unknown[]) => void);
            hooks.set(name, list);
          },
        },
        {},
        () => undefined,
      );
      const req = { url: '/pay', ip: '198.51.100.2', query: {}, body: {}, params: {}, headers: {} };
      const reply = { code: () => ({ send: () => undefined }) };
      hooks.get('preHandler')?.[0]?.(req, reply, () => undefined);
      let sent: unknown;
      hooks.get('onSend')?.[0]?.(req, reply, JSON.stringify(leaks.card), (_err: unknown, payload: unknown) => {
        sent = payload;
      });
      expect(String(sent)).not.toContain(VISA_TEST_PAN);
      expect(onEvent.mock.calls.some((c) => (c[0] as { ruleId: string }).ruleId === 'DLP-CARD-001')).toBe(true);
    });

    it('Koa inspects ctx.body after next', async () => {
      const onEvent = vi.fn();
      const mw = koaGuard({ dlp: { mode: 'mask' }, onEvent });
      const ctx = {
        method: 'GET',
        path: '/i',
        ip: '198.51.100.3',
        query: {},
        request: {},
        status: 200,
        body: undefined as unknown,
      };
      await mw(ctx, () => {
        ctx.body = leaks.internalIp;
        return Promise.resolve();
      });
      expect(JSON.stringify(ctx.body)).not.toContain('10.1.2.3');
      expect(onEvent.mock.calls.some((c) => (c[0] as { ruleId: string }).ruleId === 'DLP-INTERNAL-001')).toBe(true);
    });

    it('Hono wraps c.json for mask and block', async () => {
      const onEvent = vi.fn();
      let status: number | undefined;
      let body: unknown;
      const blockMw = honoGuard({ dlp: { mode: 'block' }, onEvent });
      const blockedCtx = {
        req: { method: 'GET', path: '/err', query: () => ({}), param: () => ({}) },
        json: (b: unknown, s?: number) => {
          body = b;
          status = s;
          return b;
        },
      };
      await blockMw(blockedCtx, () => {
        blockedCtx.json(leaks.stack, 200);
        return Promise.resolve();
      });
      expect(status).toBe(500);
      expect(body).toEqual({ error: 'internal error' });

      let masked: unknown;
      const maskMw = honoGuard({ dlp: { mode: 'mask' }, onEvent });
      const maskCtx = {
        req: { method: 'GET', path: '/me', query: () => ({}), param: () => ({}) },
        json: (b: unknown) => {
          masked = b;
          return b;
        },
      };
      await maskMw(maskCtx, () => {
        maskCtx.json(leaks.aws);
        return Promise.resolve();
      });
      expect(JSON.stringify(masked)).not.toContain(awsAccessKey());
    });
  });

  describe('runtime hygiene', () => {
    it('runtime sources do not import node:sqlite or the secrets scanner', () => {
      const dir = join(root, 'src/runtime');
      const files: string[] = [];
      const walk = (d: string): void => {
        for (const e of readdirSync(d, { withFileTypes: true })) {
          const full = join(d, e.name);
          if (e.isDirectory()) walk(full);
          else if (e.name.endsWith('.ts')) files.push(full);
        }
      };
      walk(dir);
      for (const file of files) {
        const text = readFileSync(file, 'utf8');
        expect(text, file).not.toMatch(/from\s+['"]node:sqlite['"]/);
        expect(text, file).not.toMatch(/from\s+['"][^'"]*modules\/secrets/);
      }
    });
  });
});
