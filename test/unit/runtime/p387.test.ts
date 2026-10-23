import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { blockedAddress, enabled, FLAG, FsError, literalIp, runtimeAddress, staticUrl, validateSsrfAllow } from '../../../src/runtime/exp/p387.js';

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

  it('decodes hex and dotted literals and blocks loopback addresses', () => {
    process.env[FLAG] = '1';
    try {
      expect(staticUrl('http://127.0.0.1').finding).toBe(true);
      expect(staticUrl('http://0x7f000001').finding).toBe(true);
      expect(staticUrl('not a url').finding).toBe(false);
      expect(literalIp('4294967296')).toBeNull();
      expect(literalIp('nope')).toBeNull();
      expect(blockedAddress('::1')).toBe(true);
      expect(blockedAddress('0:0:0:0:0:0:0:1')).toBe(true);
      expect(blockedAddress('127.1.2.3')).toBe(true);
      expect(blockedAddress('169.254.1.1')).toBe(true);
      expect(blockedAddress('10.0.0.1')).toBe(false);
      expect(blockedAddress('999.1.1.1')).toBe(false);
      expect(blockedAddress('::2')).toBe(false);
      expect(() => validateSsrfAllow(['169.254.169.254/32'])).toThrow(FsError);
      let resolved = 0;
      expect(runtimeAddress('127.0.0.1', () => {
        resolved += 1;
        return '203.0.113.10';
      }, []).event).toBe(true);
      expect(resolved).toBe(0);
      expect(runtimeAddress('ok.example', () => '203.0.113.10', ['ok.example'], ['169.254.169.254', '10.0.0.1', '10.0.0.2', '10.0.0.3'], 1).event).toBe(true);
      expect(runtimeAddress('ok.example', () => '203.0.113.10', ['ok.example'], ['also.example']).event).toBe(false);
    } finally {
      delete process.env[FLAG];
    }
    expect(runtimeAddress('127.0.0.1', () => '127.0.0.1', []).event).toBe(false);
  });
});
