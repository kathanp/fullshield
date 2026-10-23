/**
 * Phase 388. Deserialization sinks.
 * Off unless FULLSHIELD_EXPERIMENTAL_DESER=1.
 * Does not deserialize the payload.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DESER';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface DeserCall {
  sink: 'node-serialize' | 'js-yaml' | 'eval' | 'vm';
  schema?: 'safe' | 'default';
  origin: 'request' | 'constant' | 'json-parse-request';
}

export interface DeserFinding {
  ruleId: 'SAST-EVAL-001';
  sink: string;
  message: string;
}

export function deserFinding(call: DeserCall): DeserFinding | null {
  if (!enabled()) {
    return null;
  }
  if (call.sink === 'js-yaml' && call.schema === 'safe') {
    return null;
  }
  if (call.origin === 'constant') {
    return null;
  }
  if (call.sink === 'js-yaml' && call.origin !== 'request') {
    return null;
  }
  return {
    ruleId: 'SAST-EVAL-001',
    sink: call.sink,
    message: `Tainted value reaches ${call.sink}.`,
  };
}

export function deserRuntime(call: DeserCall, blockUnknown: boolean): { event: boolean; blocked: boolean } {
  if (!enabled()) {
    return { event: false, blocked: false };
  }
  const finding = deserFinding(call);
  if (finding === null) {
    return { event: false, blocked: false };
  }
  return { event: true, blocked: blockUnknown };
}
