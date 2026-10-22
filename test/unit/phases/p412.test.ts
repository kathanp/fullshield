import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, redirectAllows, rewriteRedirect } from '../../../src/phases/p412.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 412', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(rewriteRedirect('res.redirect(req.query.next)').edited).toBe(false);
  });

  it('rewrites a request redirect and leaves a constant target', () => {
    process.env[FLAG] = '1';
    const edited = rewriteRedirect('res.redirect(req.query.next)');
    expect(edited.edited).toBe(true);
    expect(edited.source).toContain('safeRedirect');
    expect(rewriteRedirect("res.redirect('/home')").edited).toBe(false);
    expect(redirectAllows('//evil.example', [])).toBe(false);
    expect(redirectAllows('/home', [])).toBe(true);
  });
});
