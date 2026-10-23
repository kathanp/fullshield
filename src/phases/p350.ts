/**
 * Phase 350. Bump compatibility table.
 * Off unless FULLSHIELD_EXPERIMENTAL_BUMPRISK=1.
 * The words are review, mechanical, or not-computed. There is no score.
 */

import { parseSemver } from '../modules/deps/semver.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_BUMPRISK';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type Compat = 'review' | 'mechanical' | 'not-computed';

export interface BumpInput {
  current: string;
  proposed: string;
  imports: readonly { specifier: string; dynamic: boolean }[];
  metadata?: { exports: readonly string[]; declarations: readonly string[] } | null;
}

export function bumpCompatibility(input: BumpInput): Compat | undefined {
  if (!enabled()) {
    return undefined;
  }
  const current = parseSemver(input.current);
  const proposed = parseSemver(input.proposed);
  if (current[0] !== proposed[0]) {
    return 'review';
  }
  if (input.imports.some((item) => item.dynamic)) {
    return 'not-computed';
  }
  if (input.metadata === undefined || input.metadata === null) {
    return 'not-computed';
  }
  const available = new Set<string>([...input.metadata.exports, ...input.metadata.declarations, '.']);
  const missing = input.imports.some((item) => !available.has(item.specifier) && !available.has(item.specifier.split('/').slice(1).join('/')));
  return missing ? 'review' : 'mechanical';
}
