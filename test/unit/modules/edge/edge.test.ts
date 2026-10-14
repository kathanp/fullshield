import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterAll, afterEach, describe, expect, it } from 'vitest';

import { runEdge } from '../../../../src/modules/edge/index.js';

const methods: string[] = [];
let handler: (req: IncomingMessage, res: ServerResponse) => void = (_req, res) => {
  res.statusCode = 200;
  res.end('ok');
};

const server = createServer((req, res) => {
  methods.push(`${req.method ?? '?'} ${req.url ?? ''}`);
  handler(req, res);
});

let base = '';

afterEach(() => {
  methods.length = 0;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err !== undefined && err !== null ? reject(err) : resolve()));
  });
});

async function listen(): Promise<string> {
  if (base !== '') return base;
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
  return base;
}

describe('edge posture (Phase 12)', () => {
  it('flags a missing CDN/WAF and missing security headers', async () => {
    const url = await listen();
    handler = (_req, res) => {
      res.statusCode = 200;
      res.end('ok');
    };
    const findings = await runEdge({ url, delayMs: 0 });
    const ids = new Set(findings.map((f) => f.ruleId));
    expect(ids.has('EDGE-CDN-001')).toBe(true);
    expect(ids.has('EDGE-HSTS-001')).toBe(true);
    expect(ids.has('EDGE-CSP-001')).toBe(true);
    expect(ids.has('EDGE-XCTO-001')).toBe(true);
    expect(findings.find((f) => f.ruleId === 'EDGE-CDN-001')?.severity).toBe('high');
  });

  it('does not flag CDN when cf-ray is present and required headers are set', async () => {
    const url = await listen();
    handler = (_req, res) => {
      res.setHeader('cf-ray', 'abc');
      res.setHeader('strict-transport-security', 'max-age=31536000');
      res.setHeader('content-security-policy', "default-src 'self'");
      res.setHeader('x-content-type-options', 'nosniff');
      res.setHeader('x-frame-options', 'DENY');
      res.setHeader('referrer-policy', 'no-referrer');
      res.statusCode = 200;
      res.end('ok');
    };
    const findings = await runEdge({ url, delayMs: 0 });
    const ids = new Set(findings.map((f) => f.ruleId));
    expect(ids.has('EDGE-CDN-001')).toBe(false);
    expect(ids.has('EDGE-HSTS-001')).toBe(false);
    expect(ids.has('EDGE-CSP-001')).toBe(false);
  });

  it('flags an exposed /.env and only uses GET or HEAD', async () => {
    const url = await listen();
    handler = (req, res) => {
      if (req.url === '/.env') {
        res.statusCode = 200;
        res.end('SECRET=1');
        return;
      }
      res.statusCode = 404;
      res.end();
    };
    const findings = await runEdge({ url, delayMs: 0 });
    expect(findings.some((f) => f.ruleId === 'EDGE-EXPOSE-001' && (f.file ?? '').includes('/.env'))).toBe(
      true,
    );
    expect(methods.every((m) => m.startsWith('GET ') || m.startsWith('HEAD '))).toBe(true);
    expect(methods.some((m) => m.startsWith('POST'))).toBe(false);
  });

  it('flags HTTP with no HTTPS redirect', async () => {
    const url = await listen();
    handler = (_req, res) => {
      res.statusCode = 200;
      res.end('ok');
    };
    const findings = await runEdge({ url, delayMs: 0 });
    expect(findings.some((f) => f.ruleId === 'EDGE-TLS-001')).toBe(true);
  });
});
