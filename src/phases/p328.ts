/**
 * Phase 328. WebSocket connection auth.
 * Off unless FULLSHIELD_EXPERIMENTAL_WSAUTH=1.
 * A check on one event does not cover siblings. Handlers with no sink are skipped.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_WSAUTH';
export const RULE = 'SAST-WS-AUTH-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface WsHandler {
  file: string;
  line: number;
  event: string;
  reachesSink: boolean;
  connectionAuth: boolean;
  ownCheck: boolean;
  authOrder: 'before-listen' | 'after-listen' | 'inside-success';
}

export interface WsFinding {
  ruleId: typeof RULE;
  severity: 'high';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export function wsAuthFindings(handlers: readonly WsHandler[]): WsFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: WsFinding[] = [];
  for (const handler of handlers) {
    if (!handler.reachesSink) {
      continue;
    }
    const covered = handler.authOrder === 'inside-success' || (handler.authOrder === 'before-listen' && (handler.connectionAuth || handler.ownCheck));
    if (covered) {
      continue;
    }
    findings.push({
      ruleId: RULE,
      severity: 'high',
      confidence: 'medium',
      file: handler.file,
      line: handler.line,
      message: `WebSocket event ${handler.event} reaches a sink without a dominating auth check.`,
      witness: handler.event,
    });
  }
  return findings;
}
