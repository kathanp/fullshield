/** Phase 408. Shell string to execFile. Off unless FULLSHIELD_EXPERIMENTAL_EXECFILE=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_EXECFILE';

const END_OF_OPTIONS = new Set(['git']);

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type ExecSplit = 'safe-git' | 'bare' | 'pipe' | 'already-execFile' | 'unknown-program';

export function rewriteExec(source: string, split: ExecSplit): { source: string; refused: boolean } {
  if (!enabled()) {
    return { source, refused: true };
  }
  if (split === 'already-execFile') {
    return { source, refused: false };
  }
  if (split !== 'safe-git' || !END_OF_OPTIONS.has('git') || source.includes('|')) {
    return { source, refused: true };
  }
  return { source: "execFile('git', ['show', '--', rev])", refused: false };
}
