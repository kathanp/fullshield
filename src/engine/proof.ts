/** Phase 262. A finding can carry a replayable proof. The verifier does not import this file. */
export const PROOF_FLAG = 'FULLSHIELD_EXPERIMENTAL_PROOF';

function proofEnabled(): boolean {
  return process.env[PROOF_FLAG] === '1';
}

export interface ProofStep {
  file: string;
  line: number;
  op: string;
  value: string;
}

export interface Proof {
  source: { file: string; line: number; col: number; kind: string };
  sink: { file: string; line: number; col: number; class: string };
  steps: ProofStep[];
  labelsAtSink: string[];
  sanitizersSeen: { fn: string; removed: string[] }[];
  guardsSeen: string[];
}

export function buildProof(input: {
  file: string;
  sourceLine: number;
  sinkLine: number;
  sinkClass: string;
  steps: ProofStep[];
  labelsAtSink: string[];
}): Proof | undefined {
  if (!proofEnabled()) {return undefined;}
  const first = input.steps[0];
  return {
    source: { file: input.file, line: input.sourceLine, col: 0, kind: first?.op ?? 'source' },
    sink: { file: input.file, line: input.sinkLine, col: 0, class: input.sinkClass },
    steps: input.steps,
    labelsAtSink: input.labelsAtSink,
    sanitizersSeen: [],
    guardsSeen: [],
  };
}
