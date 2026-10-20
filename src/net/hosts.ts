/** Hosts a FullShield network call may use. Phase 56 hosts are not listed until that phase is approved. */
export const ALLOWED_HOSTS = ['api.osv.dev', 'registry.npmjs.org', 'localhost', '127.0.0.1', '::1'] as const;

export function isAllowlistedHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/\.$/, '');
  for (const allowed of ALLOWED_HOSTS) {
    if (normalized === allowed) {return true;}
  }
  return false;
}
