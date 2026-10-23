/**
 * Phase 318. OAuth and OIDC client flow.
 * Off unless FULLSHIELD_EXPERIMENTAL_OAUTH=1.
 * One finding per missing edge. Does not perform a login.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_OAUTH';
const RULE = 'SAST-OAUTH-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type OAuthEdge = 'state' | 'pkce' | 'redirect_uri' | 'nonce';

export interface OAuthMachine {
  file: string;
  line: number;
  library: 'passport' | 'openid-client' | 'other';
  modelRow: boolean;
  publicClient: boolean;
  wroteState: boolean;
  comparedState: boolean;
  stateDominatesToken: boolean;
  pkce: boolean;
  redirectFrom: 'literal' | 'request' | 'none';
  acceptsIdToken: boolean;
  nonceCompared: boolean;
}

export interface OAuthFinding {
  ruleId: typeof RULE;
  severity: 'high';
  confidence: 'medium';
  file: string;
  line: number;
  edge: OAuthEdge;
  witness: OAuthEdge;
  message: string;
}

function recognized(machine: OAuthMachine): boolean {
  return machine.library === 'passport' || machine.library === 'openid-client' || machine.modelRow;
}

export function oauthFindings(machines: readonly OAuthMachine[]): OAuthFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: OAuthFinding[] = [];
  for (const machine of machines) {
    if (!recognized(machine)) {
      continue;
    }
    const edges: OAuthEdge[] = [];
    if (!(machine.wroteState && machine.comparedState && machine.stateDominatesToken)) {
      edges.push('state');
    }
    if (machine.publicClient && !machine.pkce) {
      edges.push('pkce');
    }
    if (machine.redirectFrom === 'request') {
      edges.push('redirect_uri');
    }
    if (machine.acceptsIdToken && !machine.nonceCompared) {
      edges.push('nonce');
    }
    for (const edge of edges) {
      findings.push({
        ruleId: RULE,
        severity: 'high',
        confidence: 'medium',
        file: machine.file,
        line: machine.line,
        edge,
        witness: edge,
        message: `OAuth client is missing the ${edge} edge.`,
      });
    }
  }
  return findings;
}
