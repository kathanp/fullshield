import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { enabled, FLAG, guardMessage } from '../../../src/runtime/exp/p400.js';

describe('phase 400 websocket cap', () => {
  it('delivers every message when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(guardMessage('x'.repeat(100), { maxBytes: 4 }).drop).toBe(false);
  });

  it('drops a message over the size cap and delivers one under it', () => {
    process.env[FLAG] = '1';
    expect(guardMessage('abcdef', { maxBytes: 4 }).delivered).toBe(false);
    expect(guardMessage('{"a":1}', { maxBytes: 100 }).delivered).toBe(true);
  });

  it('drops JSON that is deeper than the cap and opens no socket', () => {
    process.env[FLAG] = '1';
    expect(guardMessage('{"a":{"b":{"c":1}}}', { maxDepth: 1 }).drop).toBe(true);
    const source = readFileSync(new URL('../../../src/runtime/exp/p400.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:net');
    expect(source).not.toContain('process.exit');
  });
});
