import { afterEach, describe, expect, it } from 'vitest';

import type { AccessQuery, ModelOwner } from '../../../src/phases/p314.js';
import { enabled, FLAG, tenantFindings, type TenantAccess } from '../../../src/phases/p325.js';

const model: ModelOwner = { ownerField: 'tenantId', understood: true };

function query(over: Partial<AccessQuery> = {}): AccessQuery {
  return { filterKeys: ['tenantId'], origins: { tenantId: 'principal' }, flow: 'same-variable', mustAliasOn: false, lookupOrigin: 'principal', ...over };
}

function access(over: Partial<TenantAccess> = {}): TenantAccess {
  return { file: 't.js', line: 1, route: 'GET /items/:id', authenticated: true, query: query(), model, ...over };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 325 tenant isolation', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(tenantFindings([access({ query: query({ filterKeys: ['id'], origins: { id: 'request' }, lookupOrigin: 'request' }) })]).findings).toEqual([]);
  });

  it('accepts a tenant filter and reports a params-only load', () => {
    process.env[FLAG] = '1';
    expect(tenantFindings([access()]).findings).toEqual([]);
    const findings = tenantFindings([
      access({ query: query({ filterKeys: ['id'], origins: { id: 'request' }, lookupOrigin: 'request' }) }),
    ]).findings;
    expect(findings[0]?.ruleId).toBe('SAST-TENANT-001');
    expect(findings[0]?.message.toLowerCase()).not.toContain('returned');
  });

  it('reports a stopped edge and emits nothing for an unresolved alias', () => {
    process.env[FLAG] = '1';
    const stopped = tenantFindings([access({ relation: { literal: true, tenantOwned: false } })]).findings;
    expect(stopped.some((row) => row.witness === 'edge stopped')).toBe(true);
    expect(tenantFindings([access({ query: query({ filterKeys: 'unresolved', flow: 'may-alias' }) })]).findings).toEqual([]);
  });

  it('records a bypass and a dynamic include without a finding', () => {
    process.env[FLAG] = '1';
    const bypassed = tenantFindings([access({ bypass: 'admin' })]);
    expect(bypassed.bypasses).toEqual(['admin']);
    expect(bypassed.findings).toEqual([]);
    const dynamic = tenantFindings([access({ dynamicInclude: true })]);
    expect(dynamic.events[0]).toMatchObject({ code: 271, detail: 'dynamic include' });
    expect(dynamic.findings).toEqual([]);
    expect(tenantFindings([access({
      authenticated: false,
      query: query({ filterKeys: ['id'], origins: { id: 'request' }, lookupOrigin: 'request' }),
    })]).findings).toEqual([]);
    expect(tenantFindings([access({ relation: { literal: true, tenantOwned: true } })]).findings).toEqual([]);
    expect(tenantFindings([access({ relation: { literal: false, tenantOwned: false } })]).findings).toEqual([]);
  });
});
