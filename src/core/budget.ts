import { performance } from 'node:perf_hooks';

import type { ModuleName } from './finding.js';

/** Phase 79. Off unless this is `1`. */
export const BUDGET_FLAG = 'FULLSHIELD_EXPERIMENTAL_BUDGET';

export function budgetEnabled(): boolean {
  return process.env[BUDGET_FLAG] === '1';
}

interface BudgetState {
  deadline: number;
  incomplete: boolean;
  modules: ModuleName[];
  filesNotTaintChecked: number;
}

let active: BudgetState | undefined;
let clock: () => number = () => performance.now();

/** Tests replace the clock. Production uses `performance.now`. */
export function setBudgetClock(next: (() => number) | undefined): void {
  clock = next ?? (() => performance.now());
}

export function budgetArmed(): boolean {
  return active !== undefined;
}

export function armBudget(seconds: number): void {
  active = {
    deadline: clock() + seconds * 1000,
    incomplete: false,
    modules: [],
    filesNotTaintChecked: 0,
  };
}

export function clearBudget(): void {
  active = undefined;
}

export function budgetExpired(): boolean {
  return active !== undefined && clock() >= active.deadline;
}

/** Record that SAST stopped taint. A later smaller count does not replace a larger one. */
export function markTaintStopped(module: ModuleName, filesNotTaintChecked: number): void {
  if (active === undefined) {return;}
  active.incomplete = true;
  if (!active.modules.includes(module)) {active.modules.push(module);}
  if (filesNotTaintChecked > active.filesNotTaintChecked) {
    active.filesNotTaintChecked = filesNotTaintChecked;
  }
}

export function budgetSnapshot():
  | { incomplete: true; incompleteModules: ModuleName[]; filesNotTaintChecked: number }
  | undefined {
  if (active === undefined || !active.incomplete) {return undefined;}
  return {
    incomplete: true,
    incompleteModules: [...active.modules],
    filesNotTaintChecked: active.filesNotTaintChecked,
  };
}
