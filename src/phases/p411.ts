/** Phase 411. SSRF allowlist wrapper. Off unless FULLSHIELD_EXPERIMENTAL_SSRFWRAP=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SSRFWRAP';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function hostAllowed(host: string): boolean {
  if (host === '' || host === '*') {
    return false;
  }
  return host === 'localhost' || host.includes('.');
}

export function ssrfWrap(
  mode: 'dry-run' | 'apply',
  allow: readonly string[],
): { text: string; applied: boolean; reason: string } {
  if (!enabled()) {
    return { text: '', applied: false, reason: '' };
  }
  const listed = allow.filter((host) => hostAllowed(host));
  const helper = [
    'const ALLOW = ' + JSON.stringify(listed) + ';',
    'function allowFetch(url) {',
    '  const parsed = new URL(url);',
    '  if (!ALLOW.includes(parsed.host)) { return false; }',
    '  return parsed.protocol === "https:";',
    '}',
  ].join('\n');
  if (mode === 'apply' && listed.length === 0) {
    return { text: '', applied: false, reason: 'empty allowlist' };
  }
  return {
    text: helper,
    applied: mode === 'apply',
    reason: listed.length === 0 ? 'user must fill the list' : '',
  };
}
