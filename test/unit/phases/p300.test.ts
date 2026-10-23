import { afterEach, describe, expect, it } from 'vitest';

import { analyzeWs, enabled, FLAG } from '../../../src/phases/p300.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 300 websockets', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeWs("socket.on('chat', (payload) => { db.query(payload); });").findings).toEqual([]);
  });

  it('inherits connection auth and does not inherit a sibling check', () => {
    process.env[FLAG] = '1';
    const inherited = analyzeWs("io.use((socket, next) => next());\nsocket.on('chat', (payload) => { db.query(payload); });\nsocket.on('other', (payload) => { db.query(payload); });");
    expect(inherited.findings.map((finding) => finding.route)).toEqual(['WS chat', 'WS other']);
    expect(inherited.findings.every((finding) => finding.auth)).toBe(true);
    const sibling = analyzeWs("socket.on('chat', (payload) => { checkAuth(); db.query(payload); });\nsocket.on('other', (payload) => { db.query(payload); });");
    expect(sibling.findings.every((finding) => finding.auth)).toBe(false);
  });

  it('emits one event for a computed name and does not invent a route', () => {
    process.env[FLAG] = '1';
    const result = analyzeWs('socket.on(req.params.e, (payload) => { db.query(payload); });');
    expect(result.events).toHaveLength(1);
    expect(result.findings[0]?.route).toBeNull();
  });
});
