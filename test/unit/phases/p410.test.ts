import { afterEach, describe, expect, it } from 'vitest';

import { enabled, escapeEdit, FLAG } from '../../../src/phases/p410.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 410', () => {
  it('does nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(escapeEdit('text', false).edit).toBeNull();
  });

  it('escapes a text node and refuses the other contexts', () => {
    process.env[FLAG] = '1';
    expect(escapeEdit('text', false).edit).toBe('escapeHtml(x)');
    const url = escapeEdit('url', false);
    expect(url.edit).toBeNull();
    expect(url.diff.includes('escapeHtml')).toBe(false);
    expect(escapeEdit('script', false).edit).toBeNull();
    expect(escapeEdit('text', true).diff).toBe('');
  });
});
