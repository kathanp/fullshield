/**
 * Phase 443. Witness diagrams.
 * Off unless FULLSHIELD_EXPERIMENTAL_EXPLAIN=1.
 * Flag off: the command errors with FS-E.
 * Printed steps are capped at 40. Output is stdout text only.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_EXPLAIN';
export const STEP_CAP = 40;

class FsError extends Error {
  readonly code = 'FS-E' as const;
  constructor(message: string) {
    super(message);
    this.name = 'FsError';
  }
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface ExplainWitness {
  fingerprint: string;
  sourceFile: string;
  sinkFile: string;
  steps: readonly string[];
  sanitizers: readonly string[];
  sink: string;
  secretToken?: string;
}

export interface ExplainResult {
  exitCode: number;
  code?: 'FS-E';
  text: string;
}

export function explainWitness(fingerprint: string, witnesses: readonly ExplainWitness[]): ExplainResult {
  if (!enabled()) {
    return { exitCode: 1, code: 'FS-E', text: 'FS-E explain is experimental' };
  }
  const found = witnesses.find((row) => row.fingerprint === fingerprint);
  if (found === undefined) {
    return { exitCode: 1, code: 'FS-E', text: `FS-E unknown fingerprint ${fingerprint}` };
  }
  const truncated = found.steps.length > STEP_CAP;
  const steps = found.steps.slice(0, STEP_CAP);
  const lines = [
    `source: ${found.sourceFile}`,
    'steps:',
    ...steps.map((step) => `- ${step}`),
    ...(truncated ? ['witness was truncated'] : []),
    'sanitizers:',
    ...found.sanitizers.map((name) => `- ${name}`),
    `sink: ${found.sinkFile}`,
    found.sink,
  ];
  if (found.secretToken !== undefined) {
    lines.push(`fingerprint: ${found.fingerprint}`);
  }
  const text = lines.filter((line) => found.secretToken === undefined || !line.includes(found.secretToken)).join('\n');
  return { exitCode: 0, text };
}
