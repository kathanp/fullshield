/**
 * Phase 457. Serverless and SAM resource text.
 * Off unless FULLSHIELD_EXPERIMENTAL_SAMCFG=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Does not deploy and does not import an AWS client. Comments are not statements.
 */
import { parse as parseYaml } from 'yaml';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SAMCFG';
export const SAM_IAM = 'CONFIG-SAM-IAM-001';
export const SAM_AUTH = 'CONFIG-SAM-AUTH-001';
export const SAM_SECRET = 'CONFIG-SAM-SECRET-001';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/;

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface RouteModel {
  path: string;
  auth: 'session' | 'public';
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  snippet?: string;
}

export interface PhaseEvent {
  kind: 'parser-failure';
  file: string;
  line: number;
  reason: string;
}

export interface SamResult {
  findings: PhaseFinding[];
  events: PhaseEvent[];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function walk(value: unknown, visit: (record: Record<string, unknown>) => void): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      walk(item, visit);
    }
    return;
  }
  const record = asRecord(value);
  if (record === null) {
    return;
  }
  visit(record);
  for (const child of Object.values(record)) {
    walk(child, visit);
  }
}

function star(value: unknown): boolean {
  return value === '*' || (Array.isArray(value) && value.includes('*'));
}

function eventPath(record: Record<string, unknown>): { path: string; authed: boolean } | null {
  const http = asRecord(record.http) ?? record;
  const path = http.path ?? http.Path;
  if (typeof path !== 'string') {
    return null;
  }
  const authed = http.authorizer !== undefined || http.Auth !== undefined;
  return { path, authed };
}

export function scanSam(file: string, text: string, routes: readonly RouteModel[], baseline: readonly PhaseFinding[] = []): SamResult {
  if (!enabled()) {
    return { findings: [...baseline], events: [] };
  }
  const events: PhaseEvent[] = [];
  if (text.includes('!Ref') || text.includes('!GetAtt')) {
    events.push({ kind: 'parser-failure', file, line: 1, reason: 'unresolved intrinsic' });
  }
  const prepared = text.replace(/!Ref\s+(\S+)/g, '"$1"').replace(/!GetAtt\s+(\S+)/g, '"$1"');
  let parsed: unknown;
  try {
    parsed = parseYaml(prepared) as unknown;
  } catch {
    return { findings: [...baseline], events: [...events, { kind: 'parser-failure', file, line: 1, reason: 'yaml parse failure' }] };
  }
  const findings: PhaseFinding[] = [];
  walk(parsed, (record) => {
    if (star(record.Action) || star(record.Resource) || star(record.action) || star(record.resource)) {
      findings.push({ ruleId: SAM_IAM, severity: 'high', file, line: 1, message: "IAM Action or Resource is '*'" });
    }
    const http = eventPath(record);
    if (http === null || http.authed) {
      return;
    }
    const route = routes.find((item) => item.path === http.path);
    if (route?.auth === 'session') {
      findings.push({ ruleId: SAM_AUTH, severity: 'high', file, line: 1, message: `unauthenticated event for session route ${http.path}` });
    }
  });
  const token = SECRET.exec(text)?.[0];
  if (token !== undefined) {
    findings.push({ ruleId: SAM_SECRET, severity: 'high', file, line: 1, message: 'environment literal', snippet: `${token.slice(0, 4)}****` });
  }
  return { findings: [...baseline, ...findings], events };
}
