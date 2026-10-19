declare module '../../../bench/review-cli.mjs' {
  export function refused(env?: NodeJS.ProcessEnv, tty?: boolean): string | undefined;
  export function runReview(opts: {
    root: string;
    app: string;
    mode: 'ground-truth' | 'findings';
    lines: string[];
    tty?: boolean;
    reviewerDefault?: string;
    env?: NodeJS.ProcessEnv;
  }): { reviewer: string; wrote: string; reviewed?: boolean };
}

declare module '../../../scripts/release-checks.mjs' {
  export function packBudgetErrors(pack: {
    unpackedBytes: number;
    fileCount: number;
    hardDeps: string[];
    previousHardDeps: string[];
    packedFiles?: Array<string | { path?: string }>;
  }): string[];
}

declare module '../../../bench/holdout-run.mjs' {
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
}

declare module '../../../scripts/promotion-report.mjs' {
  export function writePromotionReports(dir: string): string[];
}
