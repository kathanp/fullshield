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
});
