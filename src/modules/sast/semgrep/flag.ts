export const SEMGREP_RULES_FLAG = 'FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES';

/** Off unless the env flag is exactly `1`. */
export function semgrepRulesEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[SEMGREP_RULES_FLAG] === '1';
}

/**
 * CLI guard. A rules path with the flag off throws before any file is read.
 * `enabled` is passed in so the caller can set the env flag first.
 */
export function guardSemgrepCli(rulesPath: string | undefined, enabled: boolean): void {
  if (rulesPath === undefined || rulesPath.length === 0 || enabled) return;
  throw new Error(`semgrep rules require ${SEMGREP_RULES_FLAG}=1`);
}
