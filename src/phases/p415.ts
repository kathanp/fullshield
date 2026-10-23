/** Phase 415. JWT verify options edit. Off unless FULLSHIELD_EXPERIMENTAL_JWTOPT=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_JWTOPT';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const BASE = 'jwt.verify(token, key)';

export function jwtOpt(key: 'pem' | 'hmac' | 'mixed' | 'unknown' | 'pss'): {
  source: string;
  refused: boolean;
} {
  if (!enabled() || key === 'mixed' || key === 'unknown' || key === 'pss') {
    return { source: BASE, refused: true };
  }
  const algorithms = key === 'pem' ? "['RS256']" : "['HS256']";
  return { source: `jwt.verify(token, key, { algorithms: ${algorithms} })`, refused: false };
}
