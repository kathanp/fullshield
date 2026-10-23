/**
 * Phase 345. Secrets in error responses.
 * Off unless FULLSHIELD_EXPERIMENTAL_ERRSECRET=1.
 * A development literal drops the stack finding. A secret field stays high.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ERRSECRET';
const RULE = 'SAST-ERRSECRET-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface ErrorResponse {
  file: string;
  line: number;
  sink: 'res.json' | 'logger.error' | 'other';
  value: 'err' | 'err-spread' | 'generic' | 'secret-field';
  env?: 'development' | 'production' | 'unknown';
  redactsStack: boolean;
  redactsSecret: boolean;
}

export interface ErrorFinding {
  ruleId: typeof RULE;
  severity: 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export function errorSecretFindings(handlers: readonly ErrorResponse[]): ErrorFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: ErrorFinding[] = [];
  for (const handler of handlers) {
    if (handler.sink !== 'res.json' || handler.value === 'generic') {
      continue;
    }
    const errorObject = handler.value === 'err' || handler.value === 'err-spread' || handler.value === 'secret-field';
    if (!errorObject) {
      continue;
    }
    if (handler.value === 'secret-field' && !handler.redactsSecret) {
      findings.push({
        ruleId: RULE,
        severity: 'high',
        file: handler.file,
        line: handler.line,
        message: 'Error response includes a secret-labeled field.',
        witness: 'secret-field',
      });
    }
    if ((handler.value === 'err' || handler.value === 'err-spread') && handler.env !== 'development' && !handler.redactsStack) {
      findings.push({
        ruleId: RULE,
        severity: 'medium',
        file: handler.file,
        line: handler.line,
        message: 'Error response may include err.stack.',
        witness: 'stack',
      });
    }
  }
  return findings;
}
