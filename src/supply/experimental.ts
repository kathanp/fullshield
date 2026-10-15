/** Phase 31 worm / VEX / overrides / provenance. Off unless the env flag or CLI option is set. */
export function experimentalVex(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_VEX === '1';
}
