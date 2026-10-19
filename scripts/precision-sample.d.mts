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
