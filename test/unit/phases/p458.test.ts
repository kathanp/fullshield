import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { EDGE_HEADER, EDGE_PUBLIC, EDGE_REDIRECT, FLAG, scanEdge } from '../../../src/phases/p458.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const token = `AKIA${'Z'.repeat(16)}`;

describe('phase 458', () => {
  it('reports a query redirect and not a same-site path', () => {
    process.env[FLAG] = '1';
    const query = scanEdge('vercel.json', JSON.stringify({ redirects: [{ source: '/r', destination: '/out?next=:next' }], headers: { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } }));
    expect(query.some((row) => row.ruleId === EDGE_REDIRECT)).toBe(true);
    const home = scanEdge('vercel.json', JSON.stringify({ redirects: [{ source: '/r', destination: '/home' }], headers: { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } }));
    expect(home.some((row) => row.ruleId === EDGE_REDIRECT)).toBe(false);
  });

  it('reports a missing Referrer-Policy and stays quiet when it is set', () => {
    process.env[FLAG] = '1';
    const missing = scanEdge('vercel.json', JSON.stringify({ headers: { 'X-Content-Type-Options': 'nosniff' } }));
    expect(missing.some((row) => row.ruleId === EDGE_HEADER && row.message.includes('Referrer-Policy') && row.severity === 'info')).toBe(true);
    const set = scanEdge('vercel.json', JSON.stringify({ headers: { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } }));
    expect(set.some((row) => row.message.includes('missing Referrer-Policy'))).toBe(false);
  });

  it('reports a public env token unless the format is publicByDesign', () => {
    process.env[FLAG] = '1';
    const hit = scanEdge('vercel.json', JSON.stringify({ headers: { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' }, env: { NEXT_PUBLIC_TOKEN: token } }));
    expect(hit.some((row) => row.ruleId === EDGE_PUBLIC)).toBe(true);
    expect(JSON.stringify(hit)).not.toContain(token);
    const format = [{ id: 'public-sample', pattern: /PUB_[A-Z0-9]+/, publicByDesign: true }];
    const skipped = scanEdge('vercel.json', JSON.stringify({ headers: { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' }, env: { NEXT_PUBLIC_TOKEN: 'PUB_ABCD' } }), format);
    expect(skipped.some((row) => row.ruleId === EDGE_PUBLIC)).toBe(false);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline = [{ ruleId: 'kept', severity: 'info' as const, file: 'vercel.json', line: 1, message: 'kept' }];
    expect(scanEdge('vercel.json', '{"redirects":[]}', undefined, baseline)).toEqual(baseline);
    const src = readFileSync(join(root, 'src/phases/p458.ts'), 'utf8');
    expect(src.includes('node:http')).toBe(false);
  });

  it('scans text config, array headers, and env values that are not public secrets', () => {
    process.env[FLAG] = '1';
    try {
      const text = [
        '[[headers]]',
        '  X-Content-Type-Options = "nosniff"',
        '  Referrer-Policy: no-referrer',
        '[[redirects]]',
        '  to = "/go?next=1"',
        '  destination = "https://evil.example/:path"',
        `  NEXT_PUBLIC_TOKEN = "${token}"`,
        '  VITE_TOKEN = "plain"',
        '  SECRET = "nope"',
      ].join('\n');
      const findings = scanEdge('netlify.toml', text);
      expect(findings.some((row) => row.ruleId === EDGE_REDIRECT)).toBe(true);
      expect(findings.some((row) => row.ruleId === EDGE_PUBLIC)).toBe(true);
      expect(JSON.stringify(findings)).not.toContain(token);

      const headers = scanEdge('vercel.json', JSON.stringify({
        headers: [{ key: 'X-Content-Type-Options' }, { name: 'Referrer-Policy' }, { other: 1 }, 'nope'],
        redirects: [{ destination: 'https://x.example/q' }, { destination: 1 }, 'nope'],
        env: { SECRET: token, NEXT_PUBLIC_TOKEN: 1, VITE_OK: 'plain' },
      }));
      expect(headers.some((row) => row.ruleId === EDGE_HEADER)).toBe(false);
      expect(headers.some((row) => row.ruleId === EDGE_PUBLIC)).toBe(false);

      const queryWord = scanEdge('vercel.json', JSON.stringify({
        redirects: [{ destination: 'next-query' }],
        headers: { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' },
      }));
      expect(queryWord.some((row) => row.ruleId === EDGE_REDIRECT)).toBe(true);
      const colon = scanEdge('vercel.json', JSON.stringify({
        redirects: [{ destination: '/out:path' }],
        headers: { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' },
      }));
      expect(colon.some((row) => row.ruleId === EDGE_REDIRECT)).toBe(true);
      const designed = [{ id: 'public-sample', pattern: /PUB_[A-Z0-9]+/, publicByDesign: true }];
      const skipped = scanEdge('netlify.toml', '  VITE_TOKEN = "PUB_ABCD"\n', designed);
      expect(skipped.some((row) => row.ruleId === EDGE_PUBLIC)).toBe(false);
    } finally {
      delete process.env[FLAG];
    }
  });
});
