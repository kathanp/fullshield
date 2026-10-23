/** Phase 419. Prototype key guard. Off unless FULLSHIELD_EXPERIMENTAL_PROTOKEY=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PROTOKEY';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface ProtoInput {
  tainted: boolean;
  callsMethod: boolean;
  constantKey?: boolean;
  freeFormMap: boolean;
}

export function protoKey(input: ProtoInput): { edit: string | null; disposition: 'safe' | 'review' | null } {
  if (!enabled() || !input.tainted || input.constantKey === true) {
    return { edit: null, disposition: null };
  }
  const disposition = input.freeFormMap ? 'review' : 'safe';
  if (input.callsMethod) {
    return {
      edit: "if (k === '__proto__' || k === 'constructor' || k === 'prototype') { throw new TypeError('prototype key'); }",
      disposition,
    };
  }
  return { edit: 'Object.create(null)', disposition };
}

export function rewriteProto(source: string, options: ProtoInput): {
  source: string;
  edit: string | null;
  refused: boolean;
  disposition: 'safe' | 'review' | null;
  witnessVerifies: boolean;
} {
  const decision = protoKey(options);
  if (!enabled()) {
    return { source, edit: null, refused: false, disposition: null, witnessVerifies: false };
  }
  if (decision.edit === null) {
    return { source, edit: null, refused: true, disposition: null, witnessVerifies: false };
  }
  const next = options.callsMethod
    ? source.replace('obj[req.body.k] = v;', `${decision.edit}\nobj[req.body.k] = v;`)
    : source.replace('obj[req.body.k] = v;', 'const obj = Object.create(null);\nobj[req.body.k] = v;');
  return { source: next, edit: decision.edit, refused: false, disposition: decision.disposition, witnessVerifies: false };
}
