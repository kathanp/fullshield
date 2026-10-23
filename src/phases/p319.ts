/**
 * Phase 319. Session configuration.
 * Off unless FULLSHIELD_EXPERIMENTAL_SESSIONCFG=1.
 * Missing secure stays low and is not dropped. csrf and _csrf skip the httpOnly check.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SESSIONCFG';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const DEFAULT_CSRF_NAMES = ['csrf', '_csrf'] as const;

export interface SessionCookie {
  file: string;
  line: number;
  name: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  secret?: { kind: 'literal'; value: string } | { kind: 'env'; name: string };
  saveUninitialized?: boolean;
  envLiteral?: 'development' | 'production';
}

export interface SessionConfig {
  extraCsrfNames?: readonly string[];
}

export interface SessionFinding {
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  confidence: 'high';
  file: string;
  line: number;
  message: string;
  secretOrigin?: boolean;
}

export function sessionFindings(cookies: readonly SessionCookie[], config: SessionConfig = {}): SessionFinding[] {
  if (!enabled()) {
    return [];
  }
  const excluded = new Set<string>([...DEFAULT_CSRF_NAMES, ...(config.extraCsrfNames ?? [])]);
  const findings: SessionFinding[] = [];
  for (const cookie of cookies) {
    if (!excluded.has(cookie.name) && cookie.httpOnly !== true) {
      findings.push({
        ruleId: 'CONFIG-SESSION-HTTPONLY-001',
        severity: 'medium',
        confidence: 'high',
        file: cookie.file,
        line: cookie.line,
        message: `Session cookie ${cookie.name} is missing httpOnly.`,
      });
    }
    if (cookie.sameSite === undefined) {
      findings.push({
        ruleId: 'CONFIG-SESSION-SAMESITE-001',
        severity: 'medium',
        confidence: 'high',
        file: cookie.file,
        line: cookie.line,
        message: `Session cookie ${cookie.name} is missing sameSite.`,
      });
    }
    if (cookie.secure !== true) {
      const dev = cookie.envLiteral === 'development' ? ' The development literal does not drop this finding.' : '';
      findings.push({
        ruleId: 'CONFIG-SESSION-SECURE-001',
        severity: 'low',
        confidence: 'high',
        file: cookie.file,
        line: cookie.line,
        message: `Session cookie ${cookie.name} is missing secure.${dev}`,
      });
    }
    if (cookie.secret?.kind === 'literal' && cookie.secret.value.length < 32) {
      findings.push({
        ruleId: 'CONFIG-SESSION-SECRET-001',
        severity: 'high',
        confidence: 'high',
        file: cookie.file,
        line: cookie.line,
        message: `Session secret literal is shorter than 32 characters (${String(cookie.secret.value.length)}).`,
        secretOrigin: true,
      });
    }
    if (cookie.saveUninitialized === true) {
      findings.push({
        ruleId: 'CONFIG-SESSION-SAVE-001',
        severity: 'info',
        confidence: 'high',
        file: cookie.file,
        line: cookie.line,
        message: 'saveUninitialized is true.',
      });
    }
  }
  return findings;
}
