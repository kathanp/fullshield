/**
 * Phase 331. Secret flow tracking.
 * Off unless FULLSHIELD_EXPERIMENTAL_SECRETFLOW=1.
 * Witness names the format id and sink class. It does not contain the secret.
 */

import { matchGrammar, type SecretFormat } from './p332.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SECRETFLOW';
export const RULE = 'SECRETS-FLOW-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const SENSITIVE_ENV = new Set(['SECRET', 'API_TOKEN', 'TOKEN', 'SESSION_SECRET']);

export interface FlowBinding {
  name: string;
  from: 'literal' | 'env' | 'binding';
  literal?: string;
  envName?: string;
  binding?: string;
}

export interface FlowSink {
  kind: 'log' | 'hmac' | 'response' | 'bundle' | 'error' | 'child';
  arg: string;
  file: string;
  line: number;
}

export interface FlowProgram {
  bindings: readonly FlowBinding[];
  sinks: readonly FlowSink[];
}

export interface FlowFinding {
  ruleId: typeof RULE;
  severity: 'high';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export interface FlowConfig {
  envNames?: readonly string[];
}

function resolveMark(name: string, bindings: readonly FlowBinding[], formats: readonly SecretFormat[], config: FlowConfig, seen: readonly string[]): string | undefined {
  if (seen.includes(name) || seen.length > 32) {
    return undefined;
  }
  const binding = [...bindings].reverse().find((item) => item.name === name);
  if (binding === undefined) {
    return undefined;
  }
  if (binding.from === 'binding' && binding.binding !== undefined) {
    return resolveMark(binding.binding, bindings, formats, config, [...seen, name]);
  }
  if (binding.from === 'env') {
    const envName = binding.envName ?? '';
    if (envName === 'NODE_ENV') {
      return undefined;
    }
    const names = new Set<string>([...SENSITIVE_ENV, ...(config.envNames ?? [])]);
    return names.has(envName) ? 'env-name' : undefined;
  }
  return matchGrammar(binding.literal ?? '', formats)?.id;
}

const SINK: Record<FlowSink['kind'], string | undefined> = {
  log: 'log',
  response: 'response',
  bundle: 'client-bundle',
  error: 'error',
  child: 'child-process',
  hmac: undefined,
};

export function secretFlow(program: FlowProgram, formats: readonly SecretFormat[], config: FlowConfig = {}): FlowFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: FlowFinding[] = [];
  for (const sink of program.sinks) {
    const sinkClass = SINK[sink.kind];
    const formatId = sinkClass === undefined ? undefined : resolveMark(sink.arg, program.bindings, formats, config, []);
    if (sinkClass === undefined || formatId === undefined) {
      continue;
    }
    findings.push({
      ruleId: RULE,
      severity: 'high',
      confidence: 'medium',
      file: sink.file,
      line: sink.line,
      message: `Secret format ${formatId} reaches sink ${sinkClass}.`,
      witness: `${formatId} ${sinkClass}`,
    });
  }
  return findings;
}
