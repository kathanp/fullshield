const KNOWN: Array<{ test: RegExp; code: string; hint: string }> = [
  {
    test: /invalid --fail-on/,
    code: 'FS-E001',
    hint: 'Use one of critical, high, medium, low, info.',
  },
  {
    test: /invalid --max-time/,
    code: 'FS-E015',
    hint: 'Pass a positive number of seconds. Set FULLSHIELD_EXPERIMENTAL_BUDGET=1 or pass --experimental-budget.',
  },
  {
    test: /unknown module/,
    code: 'FS-E002',
    hint: 'Pass a comma-separated list from `fullshield scan --help`.',
  },
  {
    test: /not a directory/,
    code: 'FS-E003',
    hint: 'Pass the project directory to scan.',
  },
  {
    test: /cannot read config/,
    code: 'FS-E004',
    hint: 'Check the path passed to --config.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_CI_REPORTS/,
    code: 'FS-E005',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1 or pass --experimental-ci-reports.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_DIFFSCAN/,
    code: 'FS-E018',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_DIFFSCAN=1 or pass --experimental-diffscan. scan --diff does not scan the whole tree when git fails.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_DIFF|scan JSON|cannot read diff/,
    code: 'FS-E006',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_DIFF=1 or pass --experimental-diff. Both inputs must be scan --json files.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_EXPLAIN|id prefix|no finding matches|ambiguous id/,
    code: 'FS-E007',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_EXPLAIN=1. Pass an id prefix of at least 6 characters from a scan JSON file.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_DEPS_DIFF|deps-diff cannot/,
    code: 'FS-E008',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_DEPS_DIFF=1. Pass a git ref that contains a lockfile.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS|sast\.sources|sast\.sanitizers/,
    code: 'FS-E009',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS=1 before naming sast.sources or sast.sanitizers.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_INGEST/,
    code: 'FS-E012',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_INGEST=1 or pass --experimental-ingest. A bad file is named with the first schema error; other files are still ingested.',
  },
  {
    test: /optional peer typescript is not installed/,
    code: 'FS-E013',
    hint: 'Install the optional peer: npm i -D typescript',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_CAPABILITIES/,
    code: 'FS-E014',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_CAPABILITIES=1 before deps --capabilities or a capability deny policy.',
  },
  {
    test: /unsupported construct|install yaml to use user-supplied semgrep rules|cannot read semgrep rules|FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES/,
    code: 'FS-E016',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES=1. An unsupported construct rejects the whole rules file.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF|cannot read npm audit file|cannot read scan JSON/,
    code: 'FS-E017',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF=1. Pass --file for an npm audit --json file you already have. --from is a scan --json file. Without --from the command reads .fullshield/last-scan.json.',
  },
  {
    test: /schedule (install could not register the timer|uninstall could not remove the timer|status could not read the timer)/,
    code: 'FS-E019',
    hint: 'The timer is a user LaunchAgent, user crontab, or scheduled task. FullShield does not use sudo.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_BUMP_PR/,
    code: 'FS-E020',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_BUMP_PR=1. The command reads a local scan JSON file and does not merge.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_PRIVATE_REG/,
    code: 'FS-E021',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_PRIVATE_REG=1. deps.registry must be https with no userinfo. The host is not contacted.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_EXCEPTIONS/,
    code: 'FS-E022',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_EXCEPTIONS=1. Each exception needs owner, reason, and an expiry within 365 days.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL/,
    code: 'FS-E023',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL=1. deps.epssFile is a local JSON file. epss is from 0 to 1.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_SAST_PARITY/,
    code: 'FS-E024',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_SAST_PARITY=1. Counts, local YAML rules, one safe fix, and HTML taint edges stay off otherwise.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_ADOPT/,
    code: 'FS-E025',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_ADOPT=1. The tour writes nothing. Digest reads a local file and does not fetch.',
  },
  {
    test: /FULLSHIELD_EXPERIMENTAL_SECTIONG/,
    code: 'FS-E026',
    hint: 'Set FULLSHIELD_EXPERIMENTAL_SECTIONG=1. These checks are local and do not fetch.',
  },
];

const DOCS = 'https://github.com/kathanp/fullshield/blob/main/docs/errors.md';

/** CLI errors keep the original message and never print a stack unless `--debug` is set. */
export function formatCliError(error: unknown, debug = process.argv.includes('--debug')): string {
  const message = error instanceof Error ? error.message : String(error);
  const known = KNOWN.find((item) => item.test.test(message));
  const code = known?.code ?? 'FS-E000';
  const hint = known !== undefined ? ` — ${known.hint} ${DOCS}#${code.toLowerCase()}` : '';
  const line = `fullshield: ${code} ${message}${hint}`;
  if (debug && error instanceof Error && error.stack !== undefined) {
    return `${line}\n${error.stack}`;
  }
  return line;
}
