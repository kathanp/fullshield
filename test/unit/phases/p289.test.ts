import { describe, expect, it } from 'vitest';

import { analyzeCrossRequest, enabled, FLAG } from '../../../src/phases/p289.js';

const SAME = `app.get('/set', (req, res) => { req.session.theme = req.query.theme; });
app.get('/page', (req, res) => { res.send(req.session.theme); });
`;

const DIFFERENT = `app.get('/set', (req, res) => { req.session.theme = req.query.theme; });
app.get('/page', (req, res) => { res.send(req.session.lang); });
`;

const DYNAMIC = `app.get('/set', (req, res) => { req.session[req.query.k] = req.query.theme; });
app.get('/page', (req, res) => { res.send(req.session.theme); });
`;

describe('phase 289 cross request', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeCrossRequest(SAME)).toEqual({ findings: [], events: [] });
  });

  it('links the same literal session key across routes', () => {
    process.env[FLAG] = '1';
    const result = analyzeCrossRequest(SAME);
    expect(result.findings[0]).toMatchObject({ origin: 'session', routes: ['/set', '/page'] });
    expect(analyzeCrossRequest(DIFFERENT).findings).toEqual([]);
  });

  it('emits an event and no finding for a dynamic key', () => {
    process.env[FLAG] = '1';
    const result = analyzeCrossRequest(DYNAMIC);
    expect(result.findings).toEqual([]);
    expect(result.events.map((event) => event.kind)).toEqual(['dynamic-property']);
  });

  it('links a session write to another route and a cache get', () => {
    process.env[FLAG] = '1';
    expect(analyzeCrossRequest(':::').findings).toEqual([]);
    const source = [
      'app.post("/in", (req) => { req.session.user = req.body.id; cache.set("card", req.query.x); cache.set(name, 1); });',
      'app.get("/out", (req) => { res.send(req.session.user); res.write(cache.get("card")); });',
      'app.get("/safe", (req) => { res.send(req.session.other); });',
      'app.get(id, () => {});',
    ].join('\n');
    const result = analyzeCrossRequest(source);
    expect(result.findings.map((row) => row.origin).sort()).toEqual(['cache', 'session']);
    expect(result.events.length).toBeGreaterThan(0);
    delete process.env[FLAG];
  });
});
