/** Phase 416. Cookie flag edit. Off unless FULLSHIELD_EXPERIMENTAL_COOKIEFLAGS=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_COOKIEFLAGS';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const FULL = "{ httpOnly: true, secure: true, sameSite: 'lax' }";

export function cookieFlags(input: {
  options: string;
  name: string;
  env: 'production' | 'development' | 'absent';
}): { source: string; reported: boolean; disposition: 'safe' | 'review' } {
  if (!enabled()) {
    return { source: input.options, reported: false, disposition: 'review' };
  }
  if (input.options.includes("sameSite: 'none'")) {
    return { source: input.options, reported: true, disposition: 'review' };
  }
  if (input.name === 'csrf' && input.options.includes('httpOnly: false')) {
    return { source: input.options, reported: false, disposition: 'review' };
  }
  if (input.options.includes('httpOnly: true') && input.options.includes("sameSite: 'lax'")) {
    return { source: input.options, reported: false, disposition: input.env === 'development' ? 'review' : 'safe' };
  }
  return {
    source: FULL,
    reported: false,
    disposition: input.env === 'development' ? 'review' : 'safe',
  };
}
