export function holdoutPlan(input: {
  release: string;
  apps: Array<{ name: string; status: string; reviewed?: boolean; firstRunDate: string | null }>;
  resultsDir: string;
  holdoutsPath: string;
  headTag: string;
  changedFiles?: string[];
}): Array<{ name: string }>;
export function runHoldout(input: {
  release: string;
  apps: Array<{ name: string; status: string; reviewed?: boolean; firstRunDate: string | null }>;
  resultsDir: string;
  holdoutsPath: string;
  headTag: string;
  changedFiles?: string[];
  today: string;
  scan: (app: { name: string }) => unknown[];
}): string[];
