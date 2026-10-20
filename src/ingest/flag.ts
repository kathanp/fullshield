export const INGEST_FLAG = 'FULLSHIELD_EXPERIMENTAL_INGEST';

/** Off unless the env flag or `--experimental-ingest` is set. */
export function ingestEnabled(explicit = false): boolean {
  return explicit || process.env.FULLSHIELD_EXPERIMENTAL_INGEST === '1';
}
