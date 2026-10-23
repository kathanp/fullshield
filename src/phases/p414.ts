/** Phase 414. Crypto API replacement. Off unless FULLSHIELD_EXPERIMENTAL_CRYPTOFIX=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CRYPTOFIX';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function cryptoFix(kind: 'password' | 'token' | 'cache-allowed' | 'interop'): {
  edit: string | null;
  safe: boolean;
  disposition: 'review' | null;
} {
  if (!enabled() || kind === 'cache-allowed') {
    return { edit: null, safe: false, disposition: null };
  }
  if (kind === 'password') {
    const edit = 'bcrypt.hash(password)';
    return { edit, safe: passwordEditIsSafe(edit), disposition: null };
  }
  if (kind === 'token') {
    return { edit: 'crypto.randomBytes(32)', safe: false, disposition: 'review' };
  }
  return { edit: "createHash('sha256')", safe: false, disposition: 'review' };
}

export function passwordEditIsSafe(edit: string | null): boolean {
  if (edit === null) {
    return false;
  }
  return edit.includes('bcrypt') || edit.includes('scrypt') || edit.includes('argon2');
}
