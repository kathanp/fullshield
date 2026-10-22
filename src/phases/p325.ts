/**
 * Phase 325. Multi-tenant isolation edge.
 * Off unless FULLSHIELD_EXPERIMENTAL_TENANT=1.
 * Reuses the phase 314 cell. Unknown scope emits nothing.
 */

import { computeOwnerCell, type AccessQuery, type ModelOwner } from './p314.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_TENANT';
export const RULE = 'SAST-TENANT-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface TenantAccess {
  file: string;
  line: number;
  route: string;
  authenticated: boolean;
  query: AccessQuery;
  model: ModelOwner | undefined;
  relation?: { literal: boolean; tenantOwned: boolean };
  dynamicInclude?: boolean;
  bypass?: string;
}

export interface TenantFinding {
  ruleId: typeof RULE;
  severity: 'high';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export interface TenantEvent {
  code: 271;
  file: string;
  detail: string;
}

export interface TenantResult {
  findings: TenantFinding[];
  events: TenantEvent[];
  bypasses: string[];
}

export function tenantFindings(accesses: readonly TenantAccess[]): TenantResult {
  if (!enabled()) {
    return { findings: [], events: [], bypasses: [] };
  }
  const findings: TenantFinding[] = [];
  const events: TenantEvent[] = [];
  const bypasses: string[] = [];
  for (const access of accesses) {
    if (access.bypass !== undefined) {
      bypasses.push(access.bypass);
      continue;
    }
    if (access.dynamicInclude === true) {
      events.push({ code: 271, file: access.file, detail: 'dynamic include' });
      continue;
    }
    const cell = computeOwnerCell(access.query, access.model);
    if (cell === 'not-scoped' && access.authenticated) {
      findings.push({
        ruleId: RULE,
        severity: 'high',
        confidence: 'medium',
        file: access.file,
        line: access.line,
        message: `Route ${access.route} is missing a tenant field on the filter.`,
        witness: access.model?.ownerField ?? 'tenant',
      });
    }
    if (access.relation?.literal === true && !access.relation.tenantOwned) {
      findings.push({
        ruleId: RULE,
        severity: 'high',
        confidence: 'medium',
        file: access.file,
        line: access.line,
        message: `Route ${access.route} stopped at a relation that is not tenant-owned.`,
        witness: 'edge stopped',
      });
    }
  }
  return { findings, events, bypasses };
}
