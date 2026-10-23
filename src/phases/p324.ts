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

function skippedHandler(handler: EnumHandler): boolean {
  if (handler.kind !== 'login' && handler.kind !== 'reset') {
    return true;
  }
  return handler.unknownUser.echoesEmail === true;
}

function armLiteral(arm: EnumArm): string {
  return arm.literal ?? '';
}

function armsDiffer(left: EnumArm, right: EnumArm): { statusDiffers: boolean; literalDiffers: boolean } {
  return { statusDiffers: left.status !== right.status, literalDiffers: armLiteral(left) !== armLiteral(right) };
}

function logOnlyDiff(left: EnumArm, right: EnumArm, statusDiffers: boolean): boolean {
  return left.logOnly === true && right.logOnly === true && !statusDiffers;
}

function enumHit(handler: EnumHandler): EnumFinding | undefined {
  if (skippedHandler(handler)) {
    return undefined;
  }
  const left = handler.unknownUser;
  const right = handler.knownUser;
  const diff = armsDiffer(left, right);
  if (!diff.statusDiffers && !diff.literalDiffers) {
    return undefined;
  }
  const logOnly = logOnlyDiff(left, right, diff.statusDiffers);
  const severity = logOnly ? 'info' : 'low';
  const message = logOnly ? 'Login or reset arms differ only in a log line.' : 'Login or reset arms differ in status or literal message.';
  return {
    ruleId: RULE,
    severity,
    confidence: 'medium',
    file: handler.file,
    line: handler.line,
    message,
    witness: `${String(left.status)}:${armLiteral(left)} | ${String(right.status)}:${armLiteral(right)}`,
  };
}

export function enumFindings(handlers: readonly EnumHandler[]): EnumFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: EnumFinding[] = [];
  for (const handler of handlers) {
    const hit = enumHit(handler);
    if (hit !== undefined) {
      findings.push(hit);
    }
  }
  return findings;
}
