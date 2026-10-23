/**
 * Phase 342. Pre-commit budget.
 * Off unless FULLSHIELD_EXPERIMENTAL_PRECOMMIT=1.
 * Scans added lines only. A budget stop exits 0. The project is not executed.
 */

import { matchGrammar, type SecretFormat } from './p332.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PRECOMMIT';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface BudgetTimer {
  elapsedMs(): number;
}

export interface PrecommitResult {
  exitCode: number;
  output: string;
  executedProject: false;
}

export function addedLines(diff: string): { file: string; line: string }[] {
  const added: { file: string; line: string }[] = [];
  let file = '';
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('+++ b/')) {
      file = raw.slice(6);
      continue;
    }
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      added.push({ file, line: raw.slice(1) });
    }
  }
  return added;
}

export function scanStaged(input: {
  diff: string;
  formats: readonly SecretFormat[];
  failOn: boolean;
  timer: BudgetTimer;
  budgetMs?: number;
}): PrecommitResult {
  const note = 'This hook is not the full scan.';
  if (!enabled()) {
    return { exitCode: 0, output: note, executedProject: false };
  }
  const budget = input.budgetMs ?? 1000;
  const files = new Set<string>();
  let found = false;
  let stopped = false;
  for (const item of addedLines(input.diff)) {
    if (!files.has(item.file) && input.timer.elapsedMs() >= budget) {
      stopped = true;
      break;
    }
    files.add(item.file);
    if (matchGrammar(item.line, input.formats) !== undefined) {
      found = true;
    }
  }
  const budgetLine = stopped ? '\nbudget stopped the scan' : '';
  const exitCode = found && input.failOn ? 1 : 0;
  return { exitCode, output: `${note}${budgetLine}`, executedProject: false };
}
