/** Phase 406. Codemod engine. Off unless FULLSHIELD_EXPERIMENTAL_CODEMOD=1. */
import { parse } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CODEMOD';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface Edit {
  fingerprint: string;
  witnessId: string;
  start: number;
  end: number;
  replacement: string;
}

export interface CodeEdit extends Edit {
  disposition: 'safe' | 'review';
  ruleId: string;
  directory: string;
}

export interface EditResult {
  applied: boolean;
  source: string;
  diff: string;
  witnessId: string;
  fingerprint: string;
}

export function dryRun(source: string, edit: Edit, dirty: boolean): EditResult {
  const unchanged: EditResult = {
    applied: false,
    source,
    diff: '',
    witnessId: edit.witnessId,
    fingerprint: edit.fingerprint,
  };
  if (!enabled() || dirty) {
    return unchanged;
  }
  const next = source.slice(0, edit.start) + edit.replacement + source.slice(edit.end);
  try {
    parse(next, { loc: false, range: false, jsx: false });
  } catch {
    return unchanged;
  }
  const removed = source.slice(edit.start, edit.end);
  return {
    applied: true,
    source: next,
    diff: `-${removed}\n+${edit.replacement}`,
    witnessId: edit.witnessId,
    fingerprint: edit.fingerprint,
  };
}

export function findNodeRange(source: string, text: string): { start: number; end: number } | null {
  const start = source.indexOf(text);
  if (start < 0) {
    return null;
  }
  return { start, end: start + text.length };
}

export function applyCodemod(
  source: string,
  edits: readonly CodeEdit[],
  dirty: boolean,
  mode: 'dry-run' | 'apply',
): { source: string; edits: CodeEdit[]; reason: string } {
  if (!enabled()) {
    return { source, edits: [], reason: 'engine off' };
  }
  if (dirty) {
    return { source, edits: [], reason: 'dirty' };
  }
  let next = source;
  const applied: CodeEdit[] = [];
  for (const edit of edits) {
    const result = dryRun(next, edit, false);
    if (!result.applied) {
      return { source, edits: [], reason: 're-parse failed' };
    }
    next = result.source;
    applied.push(edit);
  }
  return { source: next, edits: applied, reason: mode === 'dry-run' ? 'dry-run' : '' };
}
