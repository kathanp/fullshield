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
