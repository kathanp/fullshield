/** Phase 418. Secret literal to env. Off unless FULLSHIELD_EXPERIMENTAL_SECRETENV=1. */
import { createHash } from 'node:crypto';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRETENV';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

function secretName(token: string): string {
  const hash = createHash('sha256').update(token).digest('hex').slice(0, 8);
  return `SECRET_${hash}`;
}

export function secretToEnv(tokens: readonly string[]): { source: string; example: string; diff: string } {
  if (!enabled()) {
    return { source: tokens.join('\n'), example: '', diff: '' };
  }
  const names = tokens.map((token) => secretName(token));
  const source = names.map((name) => `process.env.${name}`).join('\n');
  const example = `${names.map((name) => `${name}=`).join('\n')}\n# value is not stored\n`;
  return { source, example, diff: source };
}
