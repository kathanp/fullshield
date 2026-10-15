export const COMPLIANCE_DISCLAIMER =
  'This is not a certification or audit. FullShield produces an evidence-style mapping only; it does not certify PCI DSS, SOC 2, ISO, or any other standard.';

export interface RuleMapping {
  ruleId: string;
  owasp: string;
  cwe: string;
  asvs: string;
  pci: string;
}

const ROW = (ruleId: string, owasp: string, cwe: string, asvs: string, pci: string): RuleMapping => ({
  ruleId,
  owasp,
  cwe,
  asvs,
  pci,
});

/** Every shipped rule id must appear here (Phase 23 test enforces). */
export const RULE_MAP: readonly RuleMapping[] = [
  ROW('SAST-SQLI-001', 'A03:2021 Injection', 'CWE-89', 'V5.3.4', 'PCI DSS 6.2.4'),
  ROW('SAST-NOSQLI-001', 'A03:2021 Injection', 'CWE-943', 'V5.3.4', 'PCI DSS 6.2.4'),
  ROW('SAST-CMDI-001', 'A03:2021 Injection', 'CWE-78', 'V5.3.3', 'PCI DSS 6.2.4'),
  ROW('SAST-PATH-001', 'A01:2021 Broken Access Control', 'CWE-22', 'V12.3.1', 'PCI DSS 6.2.4'),
  ROW('SAST-EVAL-001', 'A03:2021 Injection', 'CWE-95', 'V5.3.3', 'PCI DSS 6.2.4'),
  ROW('SAST-SSRF-001', 'A10:2021 SSRF', 'CWE-918', 'V12.6.1', 'PCI DSS 6.2.4'),
  ROW('SAST-REDIRECT-001', 'A01:2021 Broken Access Control', 'CWE-601', 'V5.1.1', 'PCI DSS 6.4.2'),
  ROW('SAST-PROTO-001', 'A03:2021 Injection', 'CWE-1321', 'V5.3.3', 'PCI DSS 6.2.4'),
  ROW('SAST-XSS-001', 'A03:2021 Injection', 'CWE-79', 'V5.3.3', 'PCI DSS 6.2.4'),
  ROW('SAST-JWT-001', 'A07:2021 Identification Failures', 'CWE-347', 'V3.5.3', 'PCI DSS 6.5.10'),
  ROW('SAST-CRYPTO-001', 'A02:2021 Cryptographic Failures', 'CWE-338', 'V6.2.1', 'PCI DSS 3.6 / 4.2'),
  ROW('SAST-AUTH-001', 'A07:2021 Identification Failures', 'CWE-306', 'V4.1.1', 'PCI DSS 8.2'),
  ROW('SECRET-AWS-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 3.2 / 8.3'),
  ROW('SECRET-STRIPE-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 3.2'),
  ROW('SECRET-GITHUB-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 8.3'),
  ROW('SECRET-SLACK-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 8.3'),
  ROW('SECRET-GOOGLE-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 8.3'),
  ROW('SECRET-AIKEY-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 8.3'),
  ROW('SECRET-PRIVKEY-001', 'A02:2021 Cryptographic Failures', 'CWE-321', 'V6.4.1', 'PCI DSS 3.5 / 4.2'),
  ROW('SECRET-DBURL-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 3.2 / 8.3'),
  ROW('SECRET-JWT-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 3.5'),
  ROW('SECRET-SESSION-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 3.5 / 6.2.4'),
  ROW('CONFIG-DIRLIST-001', 'A05:2021 Security Misconfiguration', 'CWE-548', 'V12.1.1', 'PCI DSS 2.2 / 6.4.3'),
  ROW('SECRET-ENVFILE-001', 'A02:2021 Cryptographic Failures', 'CWE-312', 'V8.3.4', 'PCI DSS 3.2'),
  ROW('SECRET-ENTROPY-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 8.3'),
  ROW('DEPS-VULN-001', 'A06:2021 Vulnerable Components', 'CWE-1104', 'V14.2.1', 'PCI DSS 6.3.3'),
  ROW('DEPS-MALICIOUS-001', 'A06:2021 Vulnerable Components', 'CWE-506', 'V14.2.1', 'PCI DSS 6.3.3 / 12.10'),
  ROW('DEPS-TYPOSQUAT-001', 'A06:2021 Vulnerable Components', 'CWE-494', 'V14.2.1', 'PCI DSS 6.3.3'),
  ROW('DEPS-NOLOCK-001', 'A06:2021 Vulnerable Components', 'CWE-1104', 'V14.2.1', 'PCI DSS 6.3.3'),
  ROW('DEPS-DEPRECATED-001', 'A06:2021 Vulnerable Components', 'CWE-1104', 'V14.2.1', 'PCI DSS 6.3.3'),
  ROW('CONFIG-HELMET-001', 'A05:2021 Security Misconfiguration', 'CWE-693', 'V14.4.3', 'PCI DSS 6.4.3'),
  ROW('CONFIG-BODYLIMIT-001', 'A05:2021 Security Misconfiguration', 'CWE-400', 'V13.1.1', 'PCI DSS 6.2.4'),
  ROW('CONFIG-CORS-001', 'A05:2021 Security Misconfiguration', 'CWE-942', 'V14.4.5', 'PCI DSS 6.4.3'),
  ROW('CONFIG-RATELIMIT-001', 'A07:2021 Identification Failures', 'CWE-307', 'V2.2.1', 'PCI DSS 8.3.4'),
  ROW('CONFIG-ERRSTACK-001', 'A04:2021 Insecure Design', 'CWE-209', 'V7.4.1', 'PCI DSS 6.2.4'),
  ROW('CONFIG-INSTALLSCRIPT-001', 'A06:2021 Vulnerable Components', 'CWE-829', 'V14.2.1', 'PCI DSS 6.3.3'),
  ROW('CONFIG-DOCKER-LATEST-001', 'A05:2021 Security Misconfiguration', 'CWE-1188', 'V14.1.3', 'PCI DSS 2.2'),
  ROW('CONFIG-DOCKER-ROOT-001', 'A05:2021 Security Misconfiguration', 'CWE-250', 'V14.1.3', 'PCI DSS 2.2'),
  ROW('CONFIG-DOCKER-ENV-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 3.2'),
  ROW('EDGE-CDN-001', 'A05:2021 Security Misconfiguration', 'CWE-693', 'V14.4.3', 'PCI DSS 1.2 / 6.4'),
  ROW('EDGE-CSP-001', 'A05:2021 Security Misconfiguration', 'CWE-693', 'V14.4.3', 'PCI DSS 6.4.3'),
  ROW('EDGE-EXPOSE-001', 'A05:2021 Security Misconfiguration', 'CWE-538', 'V14.4.3', 'PCI DSS 2.2 / 6.4'),
  ROW('EDGE-HSTS-001', 'A05:2021 Security Misconfiguration', 'CWE-319', 'V9.1.1', 'PCI DSS 4.2'),
  ROW('EDGE-REFERRER-001', 'A05:2021 Security Misconfiguration', 'CWE-201', 'V14.4.3', 'PCI DSS 6.4.3'),
  ROW('EDGE-TLS-001', 'A02:2021 Cryptographic Failures', 'CWE-319', 'V9.1.1', 'PCI DSS 4.2'),
  ROW('EDGE-XCTO-001', 'A05:2021 Security Misconfiguration', 'CWE-693', 'V14.4.3', 'PCI DSS 6.4.3'),
  ROW('EDGE-XFO-001', 'A05:2021 Security Misconfiguration', 'CWE-1021', 'V14.4.3', 'PCI DSS 6.4.3'),
  ROW('RASP-SQL-001', 'A03:2021 Injection', 'CWE-89', 'V5.3.4', 'PCI DSS 6.4.2'),
  ROW('RASP-SHELL-001', 'A03:2021 Injection', 'CWE-78', 'V5.3.3', 'PCI DSS 6.4.2'),
  ROW('RASP-PATH-001', 'A01:2021 Broken Access Control', 'CWE-22', 'V12.3.1', 'PCI DSS 6.4.2'),
  ROW('RASP-NOSQL-001', 'A03:2021 Injection', 'CWE-943', 'V5.3.4', 'PCI DSS 6.4.2'),
  ROW('RASP-SSRF-001', 'A10:2021 SSRF', 'CWE-918', 'V12.6.1', 'PCI DSS 1.3'),
  ROW('RASP-PROTO-001', 'A03:2021 Injection', 'CWE-1321', 'V5.3.3', 'PCI DSS 6.4.2'),
  ROW('AI-INJECT-001', 'A03:2021 Injection', 'CWE-1427', 'V5.3.3', 'PCI DSS 6.2.4'),
  ROW('LLM-001', 'A03:2021 Injection', 'CWE-1426', 'V5.3.3', 'PCI DSS 6.2.4'),
  ROW('LLM-002', 'A03:2021 Injection', 'CWE-94', 'V5.3.3', 'PCI DSS 6.2.4'),
  ROW('LLM-003', 'A01:2021 Broken Access Control', 'CWE-250', 'V4.1.1', 'PCI DSS 7.2'),
  ROW('LLM-004', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 3.2'),
  ROW('LLM-005', 'A04:2021 Insecure Design', 'CWE-770', 'V13.1.1', 'PCI DSS 6.2.4'),
  ROW('SUPPLY-INSTALLSCRIPT-001', 'A06:2021 Vulnerable Components', 'CWE-829', 'V14.2.1', 'PCI DSS 6.3.3'),
  ROW('SUPPLY-NPMRC-NET-001', 'A06:2021 Vulnerable Components', 'CWE-506', 'V14.2.1', 'PCI DSS 12.10'),
  ROW('SUPPLY-OBFUSCATE-001', 'A06:2021 Vulnerable Components', 'CWE-506', 'V14.2.1', 'PCI DSS 6.3.3'),
  ROW('SUPPLY-BEHAVIOR-001', 'A06:2021 Vulnerable Components', 'CWE-829', 'V14.2.1', 'PCI DSS 6.3.3'),
  ROW('SUPPLY-COOLDOWN-001', 'A06:2021 Vulnerable Components', 'CWE-1104', 'V14.2.1', 'PCI DSS 6.3.3'),
  ROW('SUPPLY-LOCKURL-001', 'A08:2021 Integrity Failures', 'CWE-494', 'V14.2.3', 'PCI DSS 6.3.3'),
  ROW('SUPPLY-CONFUSION-001', 'A08:2021 Integrity Failures', 'CWE-494', 'V14.2.3', 'PCI DSS 6.3.3'),
  ROW('SUPPLY-PROVENANCE-001', 'A08:2021 Integrity Failures', 'CWE-494', 'V14.2.3', 'PCI DSS 6.3.3'),
  ROW('IAC-GHA-UNPINNED-001', 'A08:2021 Integrity Failures', 'CWE-494', 'V14.2.3', 'PCI DSS 6.3.3'),
  ROW('IAC-GHA-PRTARGET-001', 'A01:2021 Broken Access Control', 'CWE-269', 'V4.1.1', 'PCI DSS 7.2'),
  ROW('IAC-GHA-PERMS-001', 'A01:2021 Broken Access Control', 'CWE-250', 'V4.1.1', 'PCI DSS 7.2'),
  ROW('IAC-GHA-SECRETLOG-001', 'A09:2021 Security Logging Failures', 'CWE-532', 'V7.1.1', 'PCI DSS 3.2 / 10.2'),
  ROW('IAC-TF-S3PUBLIC-001', 'A01:2021 Broken Access Control', 'CWE-284', 'V12.1.1', 'PCI DSS 1.3 / 3.2'),
  ROW('IAC-TF-SGOPEN-001', 'A05:2021 Security Misconfiguration', 'CWE-284', 'V1.4.1', 'PCI DSS 1.2 / 1.3'),
  ROW('IAC-TF-UNENCRYPTED-001', 'A02:2021 Cryptographic Failures', 'CWE-311', 'V6.2.1', 'PCI DSS 3.4 / 4.2'),
  ROW('IAC-K8S-PRIV-001', 'A05:2021 Security Misconfiguration', 'CWE-250', 'V14.1.3', 'PCI DSS 2.2'),
  ROW('IAC-COMPOSE-PRIV-001', 'A05:2021 Security Misconfiguration', 'CWE-250', 'V14.1.3', 'PCI DSS 2.2'),
  ROW('RASP-EGRESS-001', 'A10:2021 SSRF', 'CWE-918', 'V12.6.1', 'PCI DSS 1.3'),
  ROW('RASP-HONEY-001', 'A09:2021 Security Logging Failures', 'CWE-778', 'V7.1.1', 'PCI DSS 10.2 / 11.5'),
  ROW('RASP-FAIL-OPEN-001', 'A05:2021 Security Misconfiguration', 'CWE-755', 'V14.4.3', 'PCI DSS 6.4.3'),
  ROW('RUNTIME-SQLI-001', 'A03:2021 Injection', 'CWE-89', 'V5.3.4', 'PCI DSS 6.4.2'),
  ROW('RUNTIME-XSS-001', 'A03:2021 Injection', 'CWE-79', 'V5.3.3', 'PCI DSS 6.4.2'),
  ROW('RUNTIME-PATH-001', 'A01:2021 Broken Access Control', 'CWE-22', 'V12.3.1', 'PCI DSS 6.4.2'),
  ROW('RUNTIME-RATELIMIT-001', 'A07:2021 Identification Failures', 'CWE-307', 'V2.2.1', 'PCI DSS 8.3.4'),
  ROW('RUNTIME-BODY-001', 'A05:2021 Security Misconfiguration', 'CWE-400', 'V13.1.1', 'PCI DSS 6.2.4'),
  ROW('RUNTIME-ANOMALY-001', 'A04:2021 Insecure Design', 'CWE-754', 'V14.4.3', 'PCI DSS 10.2'),
  ROW('AI-IDOR-001', 'A01:2021 Broken Access Control', 'CWE-639', 'V4.1.1', 'PCI DSS 7.2'),
  ROW('AI-MASSASSIGN-001', 'A01:2021 Broken Access Control', 'CWE-915', 'V5.1.1', 'PCI DSS 6.2.4'),
  ROW('SECRET-BUNDLE-001', 'A02:2021 Cryptographic Failures', 'CWE-798', 'V6.4.1', 'PCI DSS 3.2 / 8.3'),
];

const byId = new Map(RULE_MAP.map((r) => [r.ruleId, r]));

export function mappingFor(ruleId: string): RuleMapping | undefined {
  return byId.get(ruleId);
}

export function renderCompliance(
  findings: Array<{ ruleId: string; severity?: string; file?: string }>,
  standard = 'pci',
): string {
  const rows = findings.map((f) => {
    const m = mappingFor(f.ruleId);
    return `${f.ruleId}\t${f.severity ?? ''}\t${f.file ?? ''}\t${m?.pci ?? 'unmapped'}\t${m?.owasp ?? ''}\t${m?.cwe ?? ''}`;
  });
  return [
    `FullShield compliance mapping (${standard})`,
    COMPLIANCE_DISCLAIMER,
    '',
    'ruleId\tseverity\tfile\tpci\towasp\tcwe',
    ...rows,
    '',
    COMPLIANCE_DISCLAIMER,
  ].join('\n');
}

export function collectRuleIdsFromSources(texts: readonly string[]): string[] {
  const ids = new Set<string>();
  const re = /\b((?:SAST|SECRET|DEPS|CONFIG|EDGE|AI|LLM|SUPPLY|IAC|RASP|RUNTIME)-[A-Z0-9]+-\d{3})\b/g;
  for (const text of texts) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) ids.add(m[1] ?? '');
  }
  return [...ids].sort();
}
