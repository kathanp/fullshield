/**
 * Phase 446. Changed-line view.
 * Off unless FULLSHIELD_EXPERIMENTAL_PRLINES=1.
 * Flag off, or without a diff: the baseline JSON is returned unchanged.
 * A diff hides untouched issues on purpose and the header says so.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PRLINES';
export const PARTIAL_HEADER = 'partial view: untouched issues are omitted from this invocation';

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface LineFinding {
  ruleId: string;
  file: string;
  line: number;
  severity: string;
  fingerprint: string;
}

export interface WitnessStep {
  fingerprint: string;
  file: string;
  line: number;
}

interface FileLines {
  added: Set<number>;
  context: Set<number>;
}

function parseDiff(diff: string): Map<string, FileLines> {
  const files = new Map<string, FileLines>();
  let current: FileLines | null = null;
  let nextLine = 0;
  for (const raw of diff.split(/\r?\n/)) {
    if (raw.startsWith('+++ b/')) {
      current = { added: new Set<number>(), context: new Set<number>() };
      files.set(raw.slice(6), current);
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk?.[1] !== undefined) {
      nextLine = Number(hunk[1]);
      continue;
    }
    if (current === null || raw.startsWith('\\')) {
      continue;
    }
    if (raw.startsWith('+')) {
      current.added.add(nextLine);
      nextLine += 1;
    } else if (raw.startsWith('-')) {
      continue;
    } else if (raw.startsWith(' ')) {
      current.context.add(nextLine);
      nextLine += 1;
    }
  }
  return files;
}

function touches(finding: LineFinding, files: Map<string, FileLines>, steps: readonly WitnessStep[]): boolean {
  const lines = files.get(finding.file);
  if (lines !== undefined && (lines.added.has(finding.line) || lines.context.has(finding.line))) {
    return true;
  }
  return steps.some((step) => {
    if (step.fingerprint !== finding.fingerprint) {
      return false;
    }
    const stepLines = files.get(step.file);
    return stepLines !== undefined && stepLines.added.has(step.line);
  });
}

export interface ChangedResult {
  json: string;
  header: string;
  fullJson: string;
}

export function changedView(
  findings: readonly LineFinding[],
  steps: readonly WitnessStep[],
  diff: string | undefined,
  baselineJson: string,
  jsonFull: boolean,
): ChangedResult {
  if (!enabled() || diff === undefined) {
    return { json: baselineJson, header: '', fullJson: baselineJson };
  }
  const files = parseDiff(diff);
  const shown = findings.filter((finding) => touches(finding, files, steps));
  const full = JSON.stringify(findings);
  return {
    json: jsonFull ? full : JSON.stringify(shown),
    header: PARTIAL_HEADER,
    fullJson: full,
  };
}
