/**
 * Phase 424. Fix rollback journal.
 * Off unless FULLSHIELD_EXPERIMENTAL_FIXJOURNAL=1.
 * Flag off: no journal entry is recorded and rollback does not change the file.
 */
import { createHash } from 'node:crypto';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FIXJOURNAL';
export const GITIGNORE_LINE = '.fullshield/fix-journal.json';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/g;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface JournalEntry {
  id: string;
  forward: string;
  reverse: string;
  hashBefore: string;
  hashAfter: string;
  restore: string;
}

function scrubSecrets(text: string): string {
  return text.replace(SECRET, (token) => `${token.slice(0, 4)}****`);
}

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

export function initGitignore(): string {
  return `${GITIGNORE_LINE}\n`;
}

export function recordApply(before: string, after: string, id: string): { text: string; journal: JournalEntry[] } {
  if (!enabled()) {
    return { text: after, journal: [] };
  }
  const entry: JournalEntry = {
    id,
    forward: scrubSecrets(after),
    reverse: scrubSecrets(before),
    hashBefore: sha256(before),
    hashAfter: sha256(after),
    restore: scrubSecrets(before),
  };
  return { text: after, journal: [entry] };
}

export function rollback(entry: JournalEntry, current: string): { text: string; refused: boolean } {
  if (!enabled()) {
    return { text: current, refused: false };
  }
  if (sha256(current) !== entry.hashAfter) {
    return { text: current, refused: true };
  }
  return { text: entry.restore, refused: false };
}
