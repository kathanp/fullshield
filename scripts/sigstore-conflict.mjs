/**
 * npm 12.2.0 ships sigstore with fetchOnConflict: false. A Rekor 409
 * ("an equivalent entry already exists") then throws TLOG_CREATE_ENTRY_ERROR
 * and the publish stops. Turning it on makes that client fetch the entry
 * Rekor already stored and keep the provenance bundle.
 */
export const PROVENANCE_TIMEOUT_MS = 120_000;

export function enableFetchOnConflict(source) {
  if (source.includes('fetchOnConflict: true') && !source.includes('fetchOnConflict: false')) {
    return source;
  }
  const needle = 'fetchOnConflict: false';
  if (!source.includes(needle)) {
    throw new Error('sigstore config has no fetchOnConflict: false');
  }
  return source.replaceAll(needle, 'fetchOnConflict: true');
}
