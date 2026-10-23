import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, idorFindings, type IdorInput } from '../../../src/phases/p315.js';

function input(over: Partial<IdorInput> = {}): IdorInput {
  return {
    route: 'PATCH /orders/:id',
    file: 'orders.js',
    line: 4,
    authKind: 'session',
    authzKind: 'none',
    scope: 'not-scoped',
    lookupOrigin: 'request',
    idSource: 'req.params.id',
    ...over,
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 315 idor edge', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(idorFindings(input())).toEqual([]);
  });

  it('emits one medium finding for an authenticated unscoped update', () => {
    process.env[FLAG] = '1';
    const findings = idorFindings(input());
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.message).toContain('PATCH /orders/:id');
    expect(findings[0]?.message).toContain('req.params.id');
    expect(findings[0]?.message).toContain('owner edge');
    expect(findings[0]?.message.toLowerCase()).not.toContain('exposed');
  });

  it('emits nothing for a scoped update, an admin route, an unauthenticated route, or unknown scope', () => {
    process.env[FLAG] = '1';
    expect(idorFindings(input({ scope: 'owner-scoped' }))).toEqual([]);
    expect(idorFindings(input({ authzKind: 'role' }))).toEqual([]);
    expect(idorFindings(input({ authKind: 'none' }))).toEqual([]);
    expect(idorFindings(input({ scope: 'unknown' }))).toEqual([]);
  });

  it('accepts jwt, apikey, passport, and framework and drops a non-request lookup', () => {
    process.env[FLAG] = '1';
    for (const authKind of ['jwt', 'apikey', 'passport:local', 'framework:nest']) {
      expect(idorFindings(input({ authKind }))).toHaveLength(1);
    }
    expect(idorFindings(input({ lookupOrigin: 'principal' }))).toEqual([]);
    expect(idorFindings(input({ authzKind: 'policy' }))).toEqual([]);
    expect(idorFindings(input({ authzKind: 'unknown' }))).toEqual([]);
    expect(idorFindings(input({ authKind: '' }))).toEqual([]);
    expect(idorFindings(input({ authKind: 'basic' }))).toEqual([]);
  });
});
