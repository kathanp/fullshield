/**
 * Phase 338. Literal secrets in CI configs.
 * Off unless FULLSHIELD_EXPERIMENTAL_CISECRET=1.
 * Vendor secret indirection is not a literal. Echo of an expression is info.
 */

import { matchGrammar, type SecretFormat } from './p332.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CISECRET';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const INDIRECTION = /\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}|\$[A-Z][A-Z0-9_]*|\$\([A-Za-z0-9_]+\)|credentials\(/;

export interface CiFinding {
  ruleId: 'SECRETS-CI-001';
  severity: 'info' | 'high';
  file: string;
  line: number;
  message: string;
}

export function ciFindings(file: string, text: string, formats: readonly SecretFormat[]): CiFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: CiFinding[] = [];
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const echoed = /\becho\b/i.test(line) && INDIRECTION.test(line) && matchGrammar(line, formats) === undefined;
    if (echoed) {
      findings.push({
        ruleId: 'SECRETS-CI-001',
        severity: 'info',
        file,
        line: index + 1,
        message: 'Echo of a CI secret expression. The runner may redact it.',
      });
      continue;
    }
    if (INDIRECTION.test(line) && matchGrammar(line, formats) === undefined) {
      continue;
    }
    const matched = matchGrammar(line, formats);
    if (matched === undefined) {
      continue;
    }
    findings.push({
      ruleId: 'SECRETS-CI-001',
      severity: 'high',
      file,
      line: index + 1,
      message: `CI config matches format ${matched.id}.`,
    });
  }
  return findings;
}
