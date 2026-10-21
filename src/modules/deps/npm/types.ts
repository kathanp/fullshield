import { makeFindingId, type Confidence, type Finding, type ModuleName, type Severity } from '../../../core/finding.js';

/** Plain compliance row. `src/compliance/index.ts` spreads these into `RULE_MAP`. */
export interface NpmDepthRow {
  ruleId: string;
  owasp: string;
  cwe: string;
  asvs: string;
  pci: string;
}

export interface NpmDepthInput {
  cwd: string;
  /** Posix-style relative paths. */
  files: readonly string[];
  manifestRaw?: string;
  /** Filename → file text for lockfiles that exist in `files`. */
  lockTexts: Readonly<Record<string, string>>;
  /** Absolute cache directory. `--offline` reads this and does not fetch. */
  cacheDir: string;
  offline: boolean;
}

export function npmFlag(name: string): boolean {
  return process.env[`FULLSHIELD_EXPERIMENTAL_${name}`] === '1';
}

export function npmRow(ruleId: string, cwe: string): NpmDepthRow {
  return {
    ruleId,
    owasp: 'A06:2021 Vulnerable Components',
    cwe,
    asvs: 'V14.2.1',
    pci: 'PCI DSS 6.3.3',
  };
}

export function npmFinding(
  ruleId: string,
  severity: Severity,
  file: string,
  snippet: string,
  title: string,
  message: string,
  remediation: string,
  confidence: Confidence = 'high',
  module: ModuleName = 'deps',
): Finding {
  return {
    id: makeFindingId(ruleId, file, snippet),
    ruleId,
    module,
    title,
    severity,
    confidence,
    file,
    snippet,
    message,
    remediation,
  };
}
