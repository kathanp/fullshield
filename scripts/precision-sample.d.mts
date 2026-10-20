export type SampleFinding = {
  id: string;
  ruleId?: string;
  file?: string;
  line?: number;
  severity?: string;
  message?: string;
  trace?: readonly { file?: string; line?: number; note?: string }[];
  label?: string | null;
  reviewer?: string | null;
  note?: string | null;
};

export function samplePerRule(
  findings: readonly SampleFinding[],
  perRule: number,
  seed: number,
): SampleFinding[];
