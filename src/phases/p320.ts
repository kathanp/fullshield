/**
 * Phase 320. Password storage and reset tokens.
 * Off unless FULLSHIELD_EXPERIMENTAL_PASSWORD=1.
 * Password length is not judged. A config skip drops only the missing-hash finding.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PASSWORD';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type HashKind = 'bcrypt' | 'scrypt' | 'argon2' | 'sha1' | 'md5' | 'plain';

export interface PasswordStore {
  file: string;
  line: number;
  field: string;
  tagged: boolean;
  hash: HashKind;
  configSkip?: boolean;
}

export interface ResetToken {
  file: string;
  line: number;
  source: 'randomBytes' | 'randomUUID' | 'other';
  bytes?: number;
  storedHashed: boolean;
  compare: 'timingSafeEqual' | 'catalog' | 'equal' | 'none';
  inQuery: boolean;
}

export interface PasswordConfig {
  fields?: readonly string[];
}

export interface PasswordFinding {
  ruleId: string;
  severity: 'medium' | 'high';
  confidence: 'high';
  file: string;
  line: number;
  message: string;
  witness: string;
}

const STRONG = new Set<HashKind>(['bcrypt', 'scrypt', 'argon2']);
const WEAK = new Set<HashKind>(['sha1', 'md5']);

function namedStore(store: PasswordStore, config: PasswordConfig): boolean {
  return store.tagged || config.fields?.includes(store.field) === true;
}

function storeFinding(store: PasswordStore, config: PasswordConfig): PasswordFinding | undefined {
  if (!namedStore(store, config)) {
    return undefined;
  }
  if (WEAK.has(store.hash)) {
    const witness = store.configSkip === true ? 'config-skip' : store.hash;
    return {
      ruleId: 'SAST-PASSWORD-WEAK-001',
      severity: 'high',
      confidence: 'high',
      file: store.file,
      line: store.line,
      message: `${store.field} is stored with ${store.hash}.`,
      witness,
    };
  }
  if (STRONG.has(store.hash) || store.configSkip === true) {
    return undefined;
  }
  return {
    ruleId: 'SAST-PASSWORD-PLAIN-001',
    severity: 'high',
    confidence: 'high',
    file: store.file,
    line: store.line,
    message: `${store.field} is stored without a catalog hash.`,
    witness: 'missing-hash',
  };
}

function pushReset(findings: PasswordFinding[], reset: ResetToken, row: Pick<PasswordFinding, 'ruleId' | 'severity' | 'message' | 'witness'>): void {
  findings.push({ ruleId: row.ruleId, severity: row.severity, confidence: 'high', file: reset.file, line: reset.line, message: row.message, witness: row.witness });
}

function shortToken(reset: ResetToken): boolean {
  return reset.source === 'randomBytes' && (reset.bytes ?? 0) < 32;
}

function resetRows(reset: ResetToken): PasswordFinding[] {
  const findings: PasswordFinding[] = [];
  if (shortToken(reset)) {
    pushReset(findings, reset, { ruleId: 'SAST-RESET-BYTES-001', severity: 'high', message: `Reset token uses randomBytes of length ${String(reset.bytes ?? 0)}.`, witness: 'short-token' });
  }
  if (reset.source === 'randomUUID') {
    pushReset(findings, reset, { ruleId: 'SAST-RESET-UUID-001', severity: 'medium', message: 'Reset token uses randomUUID.', witness: 'randomUUID' });
  }
  if (!reset.storedHashed) {
    pushReset(findings, reset, { ruleId: 'SAST-RESET-STORE-001', severity: 'high', message: 'Reset token is stored without a hash.', witness: 'reset-hash' });
  }
  if (reset.compare === 'equal') {
    pushReset(findings, reset, { ruleId: 'SAST-RESET-COMPARE-001', severity: 'high', message: 'Reset token compare uses ===.', witness: '===' });
  }
  if (reset.inQuery) {
    pushReset(findings, reset, { ruleId: 'SAST-RESET-QUERY-001', severity: 'medium', message: 'Reset token is placed in a query string.', witness: '?token=' });
  }
  return findings;
}

export function passwordFindings(
  stores: readonly PasswordStore[],
  resets: readonly ResetToken[] = [],
  config: PasswordConfig = {},
): PasswordFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: PasswordFinding[] = [];
  for (const store of stores) {
    const hit = storeFinding(store, config);
    if (hit !== undefined) {
      findings.push(hit);
    }
  }
  for (const reset of resets) {
    findings.push(...resetRows(reset));
  }
  return findings;
}
