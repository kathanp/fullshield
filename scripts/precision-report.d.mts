export type PrecisionRow = { ruleId?: string; label?: string | null };

export function renderPrecisionReport(
  input: readonly PrecisionRow[] | { rows?: readonly PrecisionRow[] },
): string;
