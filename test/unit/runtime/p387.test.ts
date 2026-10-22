import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { enabled, FLAG, FsError, runtimeAddress, staticUrl, validateSsrfAllow } from '../../../src/runtime/exp/p387.js';

describe('phase 387 SSRF addresses', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(staticUrl('http://2130706433').finding).toBe(false);
  });

  it('reports a decimal IP literal', () => {
    process.env[FLAG] = '1';
    expect(staticUrl('http://2130706433').finding).toBe(true);
  });

  it('treats a non-literal hostname as a soundness event', () => {
    process.env[FLAG] = '1';
    const result = staticUrl('https://example.invalid/x');
    expect(result.finding).toBe(false);
    expect(result.soundness).toBe(true);
  });

  it('uses the injected resolver and opens no socket', () => {
    process.env[FLAG] = '1';
    expect(runtimeAddress('example.invalid', () => '169.254.169.254', []).event).toBe(true);
    expect(runtimeAddress('example.invalid', () => '203.0.113.10', [], []).event).toBe(false);
    expect(() => validateSsrfAllow(['169.254.169.254'])).toThrow(FsError);
    const source = readFileSync(new URL('../../../src/runtime/exp/p387.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:net');
    expect(source).not.toContain('node:dns');
  });
});
