/**
 * Phase 422. Fix disposition table.
 * Off unless FULLSHIELD_EXPERIMENTAL_FIXDISP=1.
 * Flag off: the result has no disposition field.
 * safe requires a non-refused edit, a failed witness (421), and an auto-apply hole class.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FIXDISP';

export const AUTO_APPLY_HOLES = ['sql-value', 'path-prefix', 'html-text', 'cookie-missing-flag'] as const;

export type AutoApplyHole = (typeof AUTO_APPLY_HOLES)[number];
export type Disposition = 'safe' | 'review';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface DispositionInput {
  refused: boolean;
  witnessFailed: boolean;
  holeClass: string;
}

const HOLES: readonly string[] = AUTO_APPLY_HOLES;

export function dispositionOf(input: DispositionInput): { disposition?: Disposition } {
  if (!enabled() || input.refused) {
    return {};
  }
  if (input.witnessFailed && HOLES.includes(input.holeClass)) {
    return { disposition: 'safe' };
  }
  return { disposition: 'review' };
}

function walk(value: unknown, errors: string[]): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      walk(item, errors);
    }
    return;
  }
  if (typeof value !== 'object' || value === null) {
    return;
  }
  const record = value as Record<string, unknown>;
  if (typeof record.confidence === 'number') {
    errors.push('numeric confidence is rejected');
  }
  for (const key of Object.keys(record)) {
    walk(record[key], errors);
  }
}

/** Schema check. A numeric confidence field is rejected. There is no weight field. */
export function validateDispositionDocument(doc: unknown): string[] {
  const errors: string[] = [];
  walk(doc, errors);
  return errors;
}
