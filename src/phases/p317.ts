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

export function jwtFindings(calls: readonly JwtCall[]): JwtFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: JwtFinding[] = [];
  for (const call of calls) {
    if (call.kind !== 'verify') {
      continue;
    }
    const algorithms = call.algorithms ?? [];
    if (algorithms.some((name) => name.toLowerCase() === 'none')) {
      findings.push({
        ruleId: 'SAST-JWTDEEP-002',
        severity: 'critical',
        confidence: 'high',
        file: call.file,
        line: call.line,
        message: 'JWT verify allows the none algorithm.',
      });
    } else {
      const hasHmac = algorithms.some((name) => HMAC.has(name));
      const hasAsym = algorithms.some((name) => ASYMMETRIC.has(name));
      const missing = call.algorithms === undefined;
      const dangerous =
        call.algorithmsSpreadUnknown === true ||
        (hasHmac && hasAsym) ||
        (missing && (publicMaterial(call.key) || call.key === 'unknown'));
      if (dangerous) {
        findings.push({
          ruleId: 'SAST-JWTDEEP-001',
          severity: 'high',
          confidence: 'high',
          file: call.file,
          line: call.line,
          message: 'JWT verify algorithms mix HMAC and asymmetric names, or algorithms are missing for this key.',
        });
      }
    }
    if (call.issuerModel === 'third-party' && (!call.audience || !call.issuer)) {
      findings.push({
        ruleId: 'SAST-JWTDEEP-003',
        severity: 'medium',
        confidence: 'medium',
        file: call.file,
        line: call.line,
        message: 'Third-party JWT verify is missing audience or issuer.',
      });
    }
    if (call.kidFlowsTo === 'path') {
      findings.push({
        ruleId: 'SAST-PATH-001',
        severity: 'high',
        confidence: 'high',
        file: call.file,
        line: call.line,
        origin: 'jwt-header',
        message: 'kid from the JWT header reaches a file path. Origin jwt-header.',
      });
    }
    if (call.kidFlowsTo === 'sql') {
      findings.push({
        ruleId: 'SAST-SQLI-001',
        severity: 'high',
        confidence: 'high',
        file: call.file,
        line: call.line,
        origin: 'jwt-header',
        message: 'kid from the JWT header reaches a SQL query. Origin jwt-header.',
      });
    }
    if (call.headerUrlFlowsTo === 'fetch') {
      findings.push({
        ruleId: 'SAST-SSRF-001',
        severity: 'high',
        confidence: 'high',
        file: call.file,
        line: call.line,
        origin: 'jwt-header',
        message: 'jku or x5u from the JWT header reaches fetch. Origin jwt-header.',
      });
    }
  }
  return findings;
}
