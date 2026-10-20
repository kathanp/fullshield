const KNOWN: Array<{ test: RegExp; code: string; hint: string }> = [
  {
    test: /invalid --fail-on/,
    code: 'FS-E001',
    hint: 'Use one of critical, high, medium, low, info.',
  },
  {
    test: /invalid --max-time/,
    code: 'FS-E012',
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
