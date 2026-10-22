/** Phase 412. Redirect allowlist. Off unless FULLSHIELD_EXPERIMENTAL_REDIRWRAP=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_REDIRWRAP';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function redirectAllows(target: string, hosts: readonly string[]): boolean {
  if (target.startsWith('//') || target.includes('://')) {
    try {
      return hosts.includes(new URL(target).host);
    } catch {
      return false;
    }
  }
  return target.startsWith('/') && !target.includes('://');
}

export function rewriteRedirect(source: string): { source: string; edited: boolean } {
  if (!enabled()) {
    return { source, edited: false };
  }
  if (source.includes("res.redirect('/home')")) {
    return { source, edited: false };
  }
  if (!source.includes('res.redirect(req.query.next)')) {
    return { source, edited: false };
  }
  return {
    source: source.replace('res.redirect(req.query.next)', 'safeRedirect(res, req.query.next)'),
    edited: true,
  };
}
