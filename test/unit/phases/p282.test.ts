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
});
