/** Phase 27 extra SAST sinks. Off unless the env flag or CLI option is set. */
export function sastGapsEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_SAST_GAPS === '1';
}
