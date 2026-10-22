/** Phase 251. Off unless FULLSHIELD_EXPERIMENTAL_IR=1. Scan must not import this tree. */
export function irEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_IR === '1';
}
