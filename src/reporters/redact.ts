import type { ScanResult } from '../core/engine.js';
import type { Finding } from '../core/finding.js';
import { maskSecret } from '../modules/secrets/mask.js';

/** Known token shapes. Already-masked values (4 chars + ****) do not match. */
const SECRET =
  /\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[A-Za-z0-9]{10,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g;

export function redactSecrets(text: string): string {
  return text.replace(SECRET, (match) => maskSecret(match));
}

export function redactFinding(finding: Finding): Finding {
  return {
    ...finding,
    title: redactSecrets(finding.title),
    message: redactSecrets(finding.message),
    remediation: redactSecrets(finding.remediation),
    snippet: finding.snippet === undefined ? undefined : redactSecrets(finding.snippet),
  };
}

export function redactScan(result: ScanResult): ScanResult {
  return { ...result, findings: result.findings.map(redactFinding) };
}
