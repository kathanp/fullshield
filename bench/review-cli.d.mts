export function precisionReviewText(row: {
  ruleId?: string;
  file?: string;
  line?: number;
  snippet?: string;
  trace?: readonly { file?: string; line?: number; note?: string }[];
  label?: string | null;
  reviewer?: string | null;
  note?: string | null;
}): string;

export function reviewBlocked(
  env: { CI?: string; CURSOR_AGENT?: string; FULLSHIELD_AGENT?: string },
  isTTY: boolean,
): string;
