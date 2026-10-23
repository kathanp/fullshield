import { describe, expect, it } from 'vitest';

import { cspSuggestion, enabled, FLAG, LITERAL_NOTE } from '../../../src/runtime/exp/p397.js';

describe('phase 397 CSP suggestion', () => {
  it('adds no CSP section when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(cspSuggestion([{ name: 'a.html', text: '<script src="https://cdn.example.invalid/a.js"></script>' }])).toBeNull();
  });

  it('suggests the literal host and does not write a header', () => {
    process.env[FLAG] = '1';
    const suggestion = cspSuggestion([{ name: 'a.html', text: '<script src="https://cdn.example.invalid/a.js"></script>' }]);
    expect(suggestion?.section).toContain('cdn.example.invalid');
    expect(suggestion?.section).toContain(LITERAL_NOTE);
    expect(suggestion?.headerWritten).toBe(false);
  });

  it('does not suggest unsafe-inline when an inline handler is present', () => {
    process.env[FLAG] = '1';
    const suggestion = cspSuggestion([{ name: 'a.html', text: '<button onclick="go()"></button>' }]);
    expect(suggestion?.section).toContain("omit 'unsafe-inline'");
    expect(suggestion?.section).not.toContain("script-src 'unsafe-inline'");
  });

  it('ignores a comment, a broken URL, and a dynamic script reference', () => {
    process.env[FLAG] = '1';
    try {
      const suggestion = cspSuggestion([
        { name: 'a.html', text: '<a href="https://[/broken"></a><a href="https://cdn.example.invalid/a.js"></a><a href="https://cdn.example.invalid/b.js"></a><!-- <script src="https://hidden.example/a.js"></script> -->' },
        { name: 'b.tsx', text: '<script></script><img href={dynamic} />' },
      ]);
      expect(suggestion?.section).toContain('cdn.example.invalid');
      expect(suggestion?.section).toContain('strict-dynamic');
      expect(suggestion?.section).toContain("omit 'unsafe-inline'");
      expect(suggestion?.section).not.toContain('hidden.example');
      const none = cspSuggestion([{ name: 'c.html', text: '<p>hello</p>' }]);
      expect(none?.section).toContain("'none'");
      expect(none?.section).toContain("does not include 'unsafe-inline'");
    } finally {
      delete process.env[FLAG];
    }
  });
});
