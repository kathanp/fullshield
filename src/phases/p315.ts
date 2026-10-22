/**
 * Phase 315. IDOR from the ownership edge.
 * Off unless FULLSHIELD_EXPERIMENTAL_IDOR2=1.
 * Unknown scope, admin-shaped checks, and unauthenticated routes emit nothing.
 */

import type { OwnerCell } from './p314.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_IDOR2';
export const RULE = 'SAST-IDOR-002';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface IdorInput {
  route: string;
  file: string;
  line: number;
  authKind: string;
  authzKind: string;
  scope: OwnerCell | undefined;
  lookupOrigin: string;
  idSource: string;
}

export interface IdorFinding {
  ruleId: typeof RULE;
  severity: 'medium';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
}

function knownMechanism(kind: string): boolean {
  if (kind === 'none' || kind === 'unknown' || kind.length === 0) {
    return false;
  }
  return kind === 'session' || kind === 'jwt' || kind === 'apikey' || kind.startsWith('passport:') || kind.startsWith('framework:');
}

export function idorFindings(input: IdorInput): IdorFinding[] {
  if (!enabled()) {
    return [];
  }
  if (input.scope !== 'not-scoped' || !knownMechanism(input.authKind)) {
    return [];
  }
  if (input.authzKind === 'role' || input.authzKind === 'policy' || input.authzKind === 'unknown') {
    return [];
  }
  if (input.lookupOrigin !== 'request') {
    return [];
  }
  return [
    {
      ruleId: RULE,
      severity: 'medium',
      confidence: 'medium',
      file: input.file,
      line: input.line,
      message: `Route ${input.route} uses ${input.idSource} and is missing an owner edge.`,
    },
  ];
}
