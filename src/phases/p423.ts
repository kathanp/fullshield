/**
 * Phase 423. Terminal fix review.
 * Off unless FULLSHIELD_EXPERIMENTAL_FIXUI=1.
 * Flag off: non-interactive apply writes the previous safe set and does not refuse review batches.
 * Empty input and a blank line mean no. This module does not open a socket or a browser.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FIXUI';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface FixBatch {
  id: string;
  disposition: 'safe' | 'review';
  diff: string;
  path: string;
  nextText: string;
}

export interface ReviewRequest {
  batches: readonly FixBatch[];
  stdin: string;
  apply: boolean;
  applyReview: boolean;
  interactive: boolean;
}

export interface ReviewWrite {
  path: string;
  text: string;
}

export interface ReviewResult {
  exitCode: number;
  writes: ReviewWrite[];
  output: string;
  listened: false;
  browser: false;
}

function writeOf(batch: FixBatch): ReviewWrite {
  return { path: batch.path, text: batch.nextText };
}

function safeWrites(batches: readonly FixBatch[]): ReviewWrite[] {
  return batches.filter((batch) => batch.disposition === 'safe').map(writeOf);
}

function confirmed(line: string | undefined): boolean {
  return (line ?? '').trim() === 'y';
}

function prompt(batches: readonly FixBatch[], stdin: string): ReviewResult {
  const lines = stdin.split('\n');
  const writes: ReviewWrite[] = [];
  const chunks: string[] = [];
  for (let i = 0; i < batches.length; i += 1) {
    const batch = batches[i];
    if (batch === undefined) {
      continue;
    }
    chunks.push(`batch ${batch.id}\n${batch.diff}\nApply? [y/N]`);
    if (confirmed(lines[i])) {
      writes.push(writeOf(batch));
    }
  }
  return { exitCode: 0, writes, output: chunks.join('\n'), listened: false, browser: false };
}

function applyNonInteractive(request: ReviewRequest): ReviewResult {
  const review = request.batches.some((batch) => batch.disposition === 'review');
  if (review && !request.applyReview) {
    return {
      exitCode: 1,
      writes: [],
      output: 'review batch refused; use the UI or --apply-review',
      listened: false,
      browser: false,
    };
  }
  const writes = request.applyReview ? request.batches.map(writeOf) : safeWrites(request.batches);
  return { exitCode: 0, writes, output: '', listened: false, browser: false };
}

export function reviewFixes(request: ReviewRequest): ReviewResult {
  if (!enabled()) {
    if (request.apply) {
      return { exitCode: 0, writes: safeWrites(request.batches), output: '', listened: false, browser: false };
    }
    return { exitCode: 0, writes: [], output: '', listened: false, browser: false };
  }
  if (request.apply) {
    return applyNonInteractive(request);
  }
  if (request.interactive) {
    return prompt(request.batches, request.stdin);
  }
  return { exitCode: 0, writes: [], output: '', listened: false, browser: false };
}
