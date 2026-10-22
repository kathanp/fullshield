/**
 * Phase 344. Secret-manager calls.
 * Off unless FULLSHIELD_EXPERIMENTAL_SECMGR=1.
 * A manager value may reach a server sink. It must not reach a response or client bundle.
 * The literal fallback is still a secret. No network call is made.
 */

import { matchGrammar, type SecretFormat } from './p332.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECMGR';
export const HOSTS_CONTACTED: readonly string[] = [];

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const CATALOG = new Set(['getSecretValue', 'GetSecretValueCommand', 'accessSecretVersion', 'vault.read', 'getSecret']);

export interface ManagerFlow {
  file: string;
  line: number;
  callee: string;
  sink: 'sign' | 'response' | 'bundle' | 'none';
  fallbackLiteral?: string;
}

export interface ManagerFinding {
  ruleId: 'SECRETS-SECMGR-001' | 'SECRETS-FORMAT-001';
  severity: 'high';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export function hostsContacted(): readonly string[] {
  return HOSTS_CONTACTED;
}

export function managerFindings(flows: readonly ManagerFlow[], formats: readonly SecretFormat[]): ManagerFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: ManagerFinding[] = [];
  for (const flow of flows) {
    if (CATALOG.has(flow.callee) && (flow.sink === 'response' || flow.sink === 'bundle')) {
      findings.push({
        ruleId: 'SECRETS-SECMGR-001',
        severity: 'high',
        file: flow.file,
        line: flow.line,
        message: `Secret-manager value reaches ${flow.sink}.`,
        witness: 'secret-manager',
      });
    }
    if (flow.fallbackLiteral !== undefined && matchGrammar(flow.fallbackLiteral, formats) !== undefined) {
      findings.push({
        ruleId: 'SECRETS-FORMAT-001',
        severity: 'high',
        file: flow.file,
        line: flow.line,
        message: 'Literal fallback beside a secret-manager call matches a format.',
        witness: 'literal-fallback',
      });
    }
  }
  return findings;
}
