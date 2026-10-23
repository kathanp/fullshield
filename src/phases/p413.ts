/** Phase 413. NoSQL filter key guard. Off unless FULLSHIELD_EXPERIMENTAL_NOSQLGUARD=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_NOSQLGUARD';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function nosqlGuard(input: {
  schema: 'closed' | 'partial' | 'none';
  strip: boolean;
  constant: boolean;
}): { edit: string | null; disposition: 'safe' | 'review' | null } {
  if (!enabled() || input.constant) {
    return { edit: null, disposition: null };
  }
  if (input.schema === 'closed') {
    return { edit: 'pick(filter, ["id"])', disposition: 'safe' };
  }
  if (input.schema === 'partial') {
    return { edit: 'pick(filter, ["id"])', disposition: 'review' };
  }
  if (input.strip) {
    return { edit: 'stripOperators(filter)', disposition: 'review' };
  }
  return { edit: null, disposition: null };
}
