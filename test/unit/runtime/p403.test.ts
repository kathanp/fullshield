import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { createGuardedHook, enabled, FLAG } from '../../../src/runtime/exp/p403.js';

describe('phase 403 fail-open counters', () => {
  it('fail-opens on the first throw when the flag is off', () => {
    expect(enabled()).toBe(false);
    const run = createGuardedHook('sql', () => {
      throw new Error('boom');
    }, 50);
    expect(run().hookRan).toBe(true);
    expect(run().hookRan).toBe(false);
  });

  it('keeps running through 49 throws and opens on the 50th', () => {
    process.env[FLAG] = '1';
    const run = createGuardedHook('sql', () => {
      throw new Error('boom');
    }, 50);
    for (let i = 0; i < 49; i += 1) {
      const result = run();
      expect(result.hookRan).toBe(true);
      expect(result.log).toBe('');
    }
    const opened = run();
    expect(opened.log).toContain('sql');
    expect(opened.log).toContain('fail-open tripped');
    const next = run();
    expect(next.blocked).toBe(false);
    expect(next.hookRan).toBe(false);
  });

  it('does not open a socket', () => {
    const source = readFileSync(new URL('../../../src/runtime/exp/p403.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:net');
    expect(source).not.toContain('node:http');
  });
});
