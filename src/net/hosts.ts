/** Hosts a FullShield network call may use. Phase 56 hosts are not listed until that phase is approved. */
export const ALLOWED_HOSTS = ['api.osv.dev', 'registry.npmjs.org', 'localhost', '127.0.0.1', '::1'] as const;

/** Contacted only when the named flag is `1`. They are not default-scan hosts. */
export const OPT_IN_HOSTS = [
  { host: 'api.anthropic.com', flag: 'FULLSHIELD_AI_LIVE' },
  { host: 'api.openai.com', flag: 'FULLSHIELD_AI_LIVE' },
  { host: 'sts.amazonaws.com', flag: 'FULLSHIELD_EXPERIMENTAL_SECRETS_ADV' },
  { host: 'api.github.com', flag: 'FULLSHIELD_EXPERIMENTAL_SECRETS_ADV' },
  { host: 'api.stripe.com', flag: 'FULLSHIELD_EXPERIMENTAL_SECRETS_ADV' },
  { host: 'slack.com', flag: 'FULLSHIELD_EXPERIMENTAL_SECRETS_ADV' },
] as const;

export function isAllowlistedHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/\.$/, '');
  for (const allowed of ALLOWED_HOSTS) {
    if (normalized === allowed) {return true;}
  }
  for (const opt of OPT_IN_HOSTS) {
    if (normalized === opt.host && process.env[opt.flag] === '1') {return true;}
  }
  return false;
}
