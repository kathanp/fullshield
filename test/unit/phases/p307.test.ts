import { afterEach, describe, expect, it } from 'vitest';

import { analyzeMiddleware, enabled, FLAG } from '../../../src/phases/p307.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 307 middleware order', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeMiddleware("app.use('/admin', (req, res, next) => { next(); });\napp.get('/admin/x', (req, res) => {});").covers).toEqual([]);
  });

  it('covers only an earlier matching middleware that calls next', () => {
    process.env[FLAG] = '1';
    const before = analyzeMiddleware("app.use('/admin', (req, res, next) => { next(); });\napp.get('/admin/x', (req, res) => {});");
    expect(before.covers[0]).toMatchObject({ covers: true, index: 0 });
    const after = analyzeMiddleware("app.get('/admin/x', (req, res) => {});\napp.use('/admin', (req, res, next) => { next(); });");
    expect(after.covers[0]?.covers).toBe(false);
    const sibling = analyzeMiddleware("app.use('/other', (req, res, next) => { next(); });\napp.get('/admin/x', (req, res) => {});");
    expect(sibling.covers[0]?.covers).toBe(false);
    const error = analyzeMiddleware('app.use((err, req, res, next) => { next(); });\napp.get("/admin/x", (req, res) => {});');
    expect(error.covers[0]?.covers).toBe(false);
    const stopped = analyzeMiddleware("app.use('/admin', (req, res, next) => { res.send('no'); });\napp.get('/admin/x', (req, res) => {});");
    expect(stopped.covers[0]?.covers).toBe(false);
    const factory = analyzeMiddleware("function auth() { return (req, res, next) => { next(); }; }\napp.get('/x', (req, res) => {});\napp.use(auth());");
    expect(factory.covers[0]?.covers).toBe(false);
  });
});
