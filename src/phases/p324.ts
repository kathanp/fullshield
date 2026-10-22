/**
 * Phase 324. Account enumeration branches.
 * Off unless FULLSHIELD_EXPERIMENTAL_ENUM=1.
 * The wrong-password arm is not compared. Echoing an email does not use this id.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ENUM';
export const RULE = 'SAST-ENUM-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface EnumArm {
  status: number;
  literal?: string;
  logOnly?: boolean;
  echoesEmail?: boolean;
}

export interface EnumHandler {
  file: string;
  line: number;
  kind: 'login' | 'reset' | 'other';
  unknownUser: EnumArm;
  knownUser: EnumArm;
  wrongPassword?: EnumArm;
}

export interface EnumFinding {
  ruleId: typeof RULE;
  severity: 'info' | 'low';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export function enumFindings(handlers: readonly EnumHandler[]): EnumFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: EnumFinding[] = [];
  for (const handler of handlers) {
    if ((handler.kind !== 'login' && handler.kind !== 'reset') || handler.unknownUser.echoesEmail === true) {
      continue;
    }
    const left = handler.unknownUser;
    const right = handler.knownUser;
    const statusDiffers = left.status !== right.status;
    const literalDiffers = (left.literal ?? '') !== (right.literal ?? '');
    if (!statusDiffers && !literalDiffers) {
      continue;
    }
    const logOnly = left.logOnly === true && right.logOnly === true && !statusDiffers;
    findings.push({
      ruleId: RULE,
      severity: logOnly ? 'info' : 'low',
      confidence: 'medium',
      file: handler.file,
      line: handler.line,
      message: logOnly ? 'Login or reset arms differ only in a log line.' : 'Login or reset arms differ in status or literal message.',
      witness: `${String(left.status)}:${left.literal ?? ''} | ${String(right.status)}:${right.literal ?? ''}`,
    });
  }
  return findings;
}
