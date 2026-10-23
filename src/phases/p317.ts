/**
 * Phase 317. JWT verification edges.
 * Off unless FULLSHIELD_EXPERIMENTAL_JWTDEEP=1.
 * Only the verify call is judged. kid and jku reuse path, SQL, and SSRF ids.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_JWTDEEP';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const HMAC = new Set(['HS256', 'HS384', 'HS512']);
const ASYMMETRIC = new Set(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA']);

export type JwtKeyKind = 'pem-public' | 'pem-private' | 'certificate' | 'hmac' | 'unknown';

export interface JwtCall {
  kind: 'verify' | 'sign';
  file: string;
  line: number;
  algorithms?: readonly string[];
  algorithmsSpreadUnknown?: boolean;
  key: JwtKeyKind;
  audience: boolean;
  issuer: boolean;
  issuerModel: 'local' | 'third-party';
  kidFlowsTo?: 'path' | 'sql' | 'none';
  headerUrlFlowsTo?: 'fetch' | 'none';
}

export interface JwtFinding {
  ruleId: string;
  severity: 'medium' | 'high' | 'critical';
  confidence: 'medium' | 'high';
  file: string;
  line: number;
  origin?: 'jwt-header';
  message: string;
}

function publicMaterial(kind: JwtKeyKind): boolean {
  return kind === 'pem-public' || kind === 'certificate';
}

function at(call: JwtCall, draft: Pick<JwtFinding, 'ruleId' | 'severity' | 'confidence' | 'message' | 'origin'>): JwtFinding {
  const finding: JwtFinding = {
    ruleId: draft.ruleId,
    severity: draft.severity,
    confidence: draft.confidence,
    file: call.file,
    line: call.line,
    message: draft.message,
  };
  if (draft.origin !== undefined) {
    finding.origin = draft.origin;
  }
  return finding;
}

function allowsNone(algorithms: readonly string[]): boolean {
  return algorithms.some((name) => name.toLowerCase() === 'none');
}

function mixedOrMissing(call: JwtCall, algorithms: readonly string[]): boolean {
  const hasHmac = algorithms.some((name) => HMAC.has(name));
  const hasAsym = algorithms.some((name) => ASYMMETRIC.has(name));
  const missing = call.algorithms === undefined;
  const unknownKey = publicMaterial(call.key) || call.key === 'unknown';
  return call.algorithmsSpreadUnknown === true || (hasHmac && hasAsym) || (missing && unknownKey);
}

function algorithmFinding(call: JwtCall): JwtFinding | undefined {
  const algorithms = call.algorithms ?? [];
  if (allowsNone(algorithms)) {
    return at(call, { ruleId: 'SAST-JWTDEEP-002', severity: 'critical', confidence: 'high', message: 'JWT verify allows the none algorithm.' });
  }
  if (mixedOrMissing(call, algorithms)) {
    return at(call, { ruleId: 'SAST-JWTDEEP-001', severity: 'high', confidence: 'high', message: 'JWT verify algorithms mix HMAC and asymmetric names, or algorithms are missing for this key.' });
  }
  return undefined;
}

function claimFinding(call: JwtCall): JwtFinding | undefined {
  if (call.issuerModel !== 'third-party') {
    return undefined;
  }
  if (call.audience && call.issuer) {
    return undefined;
  }
  return at(call, { ruleId: 'SAST-JWTDEEP-003', severity: 'medium', confidence: 'medium', message: 'Third-party JWT verify is missing audience or issuer.' });
}

function flowFindings(call: JwtCall): JwtFinding[] {
  const findings: JwtFinding[] = [];
  if (call.kidFlowsTo === 'path') {
    findings.push(at(call, { ruleId: 'SAST-PATH-001', severity: 'high', confidence: 'high', message: 'kid from the JWT header reaches a file path. Origin jwt-header.', origin: 'jwt-header' }));
  }
  if (call.kidFlowsTo === 'sql') {
    findings.push(at(call, { ruleId: 'SAST-SQLI-001', severity: 'high', confidence: 'high', message: 'kid from the JWT header reaches a SQL query. Origin jwt-header.', origin: 'jwt-header' }));
  }
  if (call.headerUrlFlowsTo === 'fetch') {
    findings.push(at(call, { ruleId: 'SAST-SSRF-001', severity: 'high', confidence: 'high', message: 'jku or x5u from the JWT header reaches fetch. Origin jwt-header.', origin: 'jwt-header' }));
  }
  return findings;
}

function pushDefined(findings: JwtFinding[], finding: JwtFinding | undefined): void {
  if (finding !== undefined) {
    findings.push(finding);
  }
}

export function jwtFindings(calls: readonly JwtCall[]): JwtFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: JwtFinding[] = [];
  for (const call of calls) {
    if (call.kind !== 'verify') {
      continue;
    }
    pushDefined(findings, algorithmFinding(call));
    pushDefined(findings, claimFinding(call));
    findings.push(...flowFindings(call));
  }
  return findings;
}
