const SPDX_FLAG = 'FULLSHIELD_EXPERIMENTAL_SPDX';

/** Phase 89. Off unless the env flag or `--experimental-spdx` is set. */
export function experimentalSpdxEnabled(cliFlag = false): boolean {
  return cliFlag || process.env[SPDX_FLAG] === '1';
}
