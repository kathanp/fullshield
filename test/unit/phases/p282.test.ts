import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p282.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 282', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeHtml('const html = `<div>${req.query.x}</div>`;').findings).toEqual([]);
  });

  it('reports an unsanitized text hole and clears a text node that is escaped', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeHtml('const html = `<div>${req.query.x}</div>`;').findings.length).toBeGreaterThan(0);
    expect(phase.sanitizerClears('text', 'escapeHtml')).toBe(true);
    expect(phase.htmlContextOf('<div>')).toBe('text');
  });

  it('classifies attributes, scripts, comments, and sanitizers', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeHtml(':::').findings).toEqual([]);
    expect(phase.sanitizerClears('script', 'none')).toBe(false);
    expect(phase.sanitizerClears('text', 'jsonStringify')).toBe(false);
    expect(phase.sanitizerClears('text', 'encodeURIComponent')).toBe(false);
    expect(phase.sanitizerClears('quoted-attr', 'escapeHtml')).toBe(true);
    expect(phase.sanitizerClears('script', 'escapeHtml')).toBe(false);
    expect(phase.sanitizerClears('text', 'textContent')).toBe(true);
    expect(phase.sanitizerClears('script', 'textContent')).toBe(false);
    expect(phase.sanitizerClears('comment', 'dompurify')).toBe(true);
    expect(phase.sanitizerClears('script', 'dompurify')).toBe(false);
    const snippets = [
      '`<div class="${req.query.x}">`',
      '`<a href=${req.query.x}>`',
      '`<a href="${req.query.x}">`',
      '`<div onclick="${req.query.x}">`',
      '`<script>${req.query.x}</script>`',
      '`<style>${req.query.x}</style>`',
      '`<!--${req.query.x}-->`',
      '`<div>${escapeHtml(req.query.x)}</div>`',
      '`<div>${encodeURIComponent(req.query.x)}</div>`',
      '`<script>${JSON.stringify(req.query.x)}</script>`',
      '`<div>${DOMPurify.sanitize(req.query.x)}</div>`',
      '`<img src=${name}>`',
      '`<script>ok</script><b>${req.query.x}</b>`',
      '`<style>ok</style><b>${req.query.x}</b>`',
      '`<!--ok-->${req.query.x}`',
      '`<a href="http://x" title="${req.query.x}">`',
      '`<div>${JSON(req.query.x)}</div>`',
      '`<div>${(0, escapeHtml)(req.query.x)}</div>`',
    ];
    const contexts = snippets.flatMap((snippet) => phase.analyzeHtml(`const html = ${snippet};`).findings.map((row) => row.htmlContext));
    expect(contexts).toContain('quoted-attr');
    expect(contexts).toContain('script');
    expect(contexts).toContain('comment');
    delete process.env[phase.FLAG];
  });
});
