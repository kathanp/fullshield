import { describe, expect, it } from 'vitest';

import { applyEol, detectEol, normalizeNewlines } from '../../../src/fixer/eol.js';

describe('newline helpers (Phase 25)', () => {
  it('detects CRLF when any \\r\\n is present', () => {
    expect(detectEol('a\r\nb\n')).toBe('\r\n');
    expect(detectEol('a\nb\n')).toBe('\n');
  });

  it('normalizes mixed endings before compare', () => {
    expect(normalizeNewlines('a\r\nb\rc\n')).toBe('a\nb\nc\n');
  });

  it('restores CRLF onto a normalized patch result', () => {
    expect(applyEol('a\nb\n', '\r\n')).toBe('a\r\nb\r\n');
    expect(applyEol('a\r\nb\r\n', '\n')).toBe('a\nb\n');
  });
});
