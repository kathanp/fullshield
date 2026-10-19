declare module '../../../scripts/precision-report.mjs' {
  export function wilsonInterval(
    successes: number,
    total: number,
    z?: number,
  ): { low: number; high: number };
  export function precisionReport(rows: Array<{ ruleId: string; label: string | null }>): string;
}

declare module '../../../scripts/precision-sample.mjs' {
  export function sampleFindings(
    findings: Array<{ ruleId: string; file?: string; line?: number; severity: string; id: string }>,
    perRule: number,
    seed: number,
  ): Array<{
    ruleId: string;
    file: string;
    line: number;
    severity: string;
    id: string;
    label: null;
    reviewer: null;
    note: null;
  }>;
}
