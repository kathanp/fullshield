/**
 * Phase 448. Streaming scan API.
 * Off unless FULLSHIELD_EXPERIMENTAL_STREAMAPI=1.
 * Flag off: the iterator is absent from the experimental export list.
 * scanFindingsIterator yields findings as they finish. Order is not the scan --json order.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_STREAMAPI';

export const ITERATOR_DOC =
  'scanFindingsIterator yields findings as they finish. Order is not the scan --json order.';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface StreamFinding {
  ruleId: string;
  file: string;
  line: number;
  severity: string;
}

export function scanJson(findings: readonly StreamFinding[]): StreamFinding[] {
  return [...findings].sort((left, right) => left.ruleId.localeCompare(right.ruleId) || left.line - right.line);
}

export async function* scanFindingsIterator(
  findings: readonly StreamFinding[],
  signal?: AbortSignal,
): AsyncGenerator<StreamFinding> {
  for (const finding of findings) {
    if (signal?.aborted === true) {
      return;
    }
    await Promise.resolve();
    yield finding;
  }
}

export function exportNames(): readonly string[] {
  const names = ['scanJson'];
  if (enabled()) {
    names.push('scanFindingsIterator');
  }
  return names;
}

/** This phase does not start a worker. The list stays empty after cancellation. */
export function childProcesses(): readonly number[] {
  return [];
}
