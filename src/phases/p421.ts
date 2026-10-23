/**
 * Phase 421. Fix verification on the witness.
 * Off unless FULLSHIELD_EXPERIMENTAL_FIXVERIFY2=1.
 * Flag off: the after-text and baseline ids are returned unchanged and the fix is not marked safe.
 * The checker does not run the project or its tests.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FIXVERIFY2';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface WitnessRef {
  ruleId: string;
  file: string;
  line: number;
}

export interface VerifyInput {
  witness: WitnessRef;
  before: string;
  after: string;
  /** A refused edit is a no-op. */
  refused?: boolean;
  baselineIds: readonly string[];
}

export interface VerifyResult {
  after: string;
  eligibleSafe: boolean;
  witnessFailed: boolean;
  failedRuleId: string | null;
  failedLine: number | null;
  baselineIds: readonly string[];
  commands: readonly string[];
  processes: readonly string[];
}

function lineAt(source: string, line: number): string {
  const rows = source.split(/\r?\n/);
  return rows[line - 1] ?? '';
}

function isQueryCall(line: string): boolean {
  return /\.query\s*\(/.test(line);
}

/** True while a SQL call still concatenates or interpolates a value. */
function sqlSinkOpen(line: string): boolean {
  if (!isQueryCall(line)) {
    return false;
  }
  return /\+\s*[A-Za-z_$]/.test(line) || /\$\{/.test(line);
}

function witnessHolds(source: string, witness: WitnessRef): boolean {
  if (witness.ruleId !== 'SAST-SQLI-001') {
    return false;
  }
  return sqlSinkOpen(lineAt(source, witness.line));
}

function passthrough(input: VerifyInput): VerifyResult {
  return {
    after: input.after,
    eligibleSafe: false,
    witnessFailed: false,
    failedRuleId: null,
    failedLine: null,
    baselineIds: input.baselineIds,
    commands: [],
    processes: [],
  };
}

export function verifyFix(input: VerifyInput): VerifyResult {
  if (!enabled() || input.refused === true) {
    return passthrough(input);
  }
  const line = lineAt(input.after, input.witness.line);
  const sameSink = input.witness.ruleId === 'SAST-SQLI-001' && isQueryCall(line);
  const witnessFailed = sameSink && !witnessHolds(input.after, input.witness);
  return {
    after: input.after,
    eligibleSafe: witnessFailed,
    witnessFailed,
    failedRuleId: witnessFailed ? input.witness.ruleId : null,
    failedLine: witnessFailed ? input.witness.line : null,
    baselineIds: input.baselineIds,
    commands: [],
    processes: [],
  };
}

/** A different line cannot satisfy this witness, even when that line is also a bug. */
export function satisfiesWitness(source: string, witness: WitnessRef, candidateLine: number): boolean {
  if (candidateLine !== witness.line) {
    return false;
  }
  const line = lineAt(source, witness.line);
  return isQueryCall(line) && !witnessHolds(source, witness);
}
