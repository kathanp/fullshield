import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { enabled, FLAG, KEY_PREFIX, openCounter } from '../../../src/runtime/exp/p392.js';

describe('phase 392 redis counters', () => {
  it('does not import a client when redis is not selected', async () => {
    process.env[FLAG] = '1';
    let calls = 0;
    const counter = await openCounter({ store: 'memory' }, () => {
      calls += 1;
      return Promise.resolve(null);
    });
    expect(calls).toBe(0);
    expect(counter.imported).toBe(false);
    await counter.set('ip', 1);
  });

  it('fails with the install message when the package is missing', async () => {
    process.env[FLAG] = '1';
    await expect(openCounter({ store: 'redis', url: 'redis://127.0.0.1:6379' }, () => Promise.resolve(null))).rejects.toThrow(/install redis or ioredis/);
  });

  it('stores the count under the prefix and not a request body', async () => {
    process.env[FLAG] = '1';
    const seen: Array<{ key: string; value: number }> = [];
    const counter = await openCounter({ store: 'redis', url: 'redis://127.0.0.1:6379' }, () => Promise.resolve({
      set(key: string, value: number) {
        seen.push({ key, value });
      },
    }));
    await counter.set('ip', 3);
    expect(seen).toEqual([{ key: `${KEY_PREFIX}ip`, value: 3 }]);
    expect(JSON.stringify(seen)).not.toContain('password');
    const source = readFileSync(new URL('../../../src/runtime/exp/p392.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('src/modules');
    expect(source).not.toContain('src/core');
    expect(KEY_PREFIX).not.toBe('');
  });

  it('does not load redis when the flag is off', async () => {
    expect(enabled()).toBe(false);
    let calls = 0;
    await openCounter({ store: 'redis', url: 'redis://127.0.0.1:6379' }, () => {
      calls += 1;
      return Promise.resolve(null);
    });
    expect(calls).toBe(0);
  });

  it('rejects a non-integer count and a redis config without a url', async () => {
    process.env[FLAG] = '1';
    try {
      const memory = await openCounter({ store: 'memory' }, () => Promise.resolve(null));
      expect(() => memory.set('ip', 1.5)).toThrow(/integer/);
      await expect(openCounter({ store: 'redis' }, () => Promise.resolve(null))).rejects.toThrow(/no URL/);
      await expect(openCounter({ store: 'redis', url: '' }, () => Promise.resolve(null))).rejects.toThrow(/no URL/);
      const seen: number[] = [];
      const redis = await openCounter({ store: 'redis', url: 'redis://127.0.0.1:6379' }, (name) => {
        if (name === 'redis') {return Promise.resolve(null);}
        return Promise.resolve({
          set(_key: string, value: number) {
            seen.push(value);
          },
        });
      });
      expect(redis.imported).toBe(true);
      await redis.set('ip', 4);
      expect(seen).toEqual([4]);
      await expect(redis.set('ip', 1.2)).rejects.toThrow(/integer/);
    } finally {
      delete process.env[FLAG];
    }
  });
});
