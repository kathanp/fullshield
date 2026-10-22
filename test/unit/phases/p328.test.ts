import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, wsAuthFindings, type WsHandler } from '../../../src/phases/p328.js';

function handler(over: Partial<WsHandler> = {}): WsHandler {
  return {
    file: 'ws.js',
    line: 2,
    event: 'message',
    reachesSink: true,
    connectionAuth: true,
    ownCheck: false,
    authOrder: 'before-listen',
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 328 websocket auth', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(wsAuthFindings([handler({ connectionAuth: false })])).toEqual([]);
  });

  it('accepts connection auth and reports an unauthenticated sibling', () => {
    process.env[FLAG] = '1';
    expect(wsAuthFindings([handler()])).toEqual([]);
    const sibling = wsAuthFindings([handler({ event: 'admin', connectionAuth: false })]);
    expect(sibling[0]?.witness).toBe('admin');
  });

  it('skips an ack-only handler and reports auth registered after on', () => {
    process.env[FLAG] = '1';
    expect(wsAuthFindings([handler({ reachesSink: false, connectionAuth: false })])).toEqual([]);
    expect(wsAuthFindings([handler({ authOrder: 'after-listen', connectionAuth: true })])).toHaveLength(1);
    const source = readFileSync(new URL('../../../src/phases/p328.ts', import.meta.url), 'utf8');
    expect(source.includes('socket.on')).toBe(false);
  });
});
